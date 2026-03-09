use aes_gcm::aead::Aead;
use aes_gcm::{AeadCore, Aes128Gcm, AesGcm, KeyInit};
use rocksdb::IteratorMode;
use std::collections::BTreeSet;
use std::fmt::Display;
use std::path::Path;
use std::sync::Arc;

pub const EPOCH_ID_KEY: &[u8] = b"EPOCH_ID";

/// Key-value store that encrypts all values with AES-GCM.
pub struct SecretDB {
    db: rocksdb::DB,
    cipher: Aes128Gcm,
}

impl std::fmt::Debug for SecretDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretDB").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DBCol {
    Triple,
    Presignature,
    EpochData,
    Keyshare,
}

impl DBCol {
    fn as_str(&self) -> &'static str {
        match self {
            DBCol::Triple => "triple",
            DBCol::Presignature => "presignature",
            DBCol::EpochData => "epoch_id",
            DBCol::Keyshare => "keyshare",
        }
    }

    fn all() -> [DBCol; 4] {
        [
            DBCol::Triple,
            DBCol::Presignature,
            DBCol::EpochData,
            DBCol::Keyshare,
        ]
    }
}

impl Display for DBCol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub fn encrypt(cipher: &Aes128Gcm, plaintext: &[u8]) -> Vec<u8> {
    let nonce = aes_gcm::Aes128Gcm::generate_nonce(&mut rand::thread_rng());
    let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();
    [nonce.as_ref(), ciphertext.as_slice()].concat()
}

pub fn decrypt(cipher: &Aes128Gcm, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    const NONCE_LEN: usize = 12;
    if ciphertext.len() < NONCE_LEN {
        return Err(anyhow::anyhow!("ciphertext is too short"));
    }
    let nonce = &ciphertext[..NONCE_LEN];
    let ciphertext = &ciphertext[NONCE_LEN..];
    let data = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed"))?;
    Ok(data)
}

impl SecretDB {
    pub fn new(path: &Path, encryption_key: [u8; 16]) -> anyhow::Result<Arc<Self>> {
        let cipher = AesGcm::new(&encryption_key.into());
        let mut options = rocksdb::Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        let known_cfs: BTreeSet<String> = DBCol::all()
            .iter()
            .map(|col| col.as_str().to_string())
            .collect();
        let on_disk_cfs: BTreeSet<String> = rocksdb::DB::list_cf(&options, path)
            .unwrap_or_default()
            .into_iter()
            .collect();
        let all_cfs: Vec<&String> = known_cfs.union(&on_disk_cfs).collect();
        let db = rocksdb::DB::open_cf(&options, path, &all_cfs)?;
        Ok(Self { db, cipher }.into())
    }

    fn cf_handle(&self, cf: DBCol) -> rocksdb::ColumnFamilyRef<'_> {
        self.db.cf_handle(cf.as_str()).unwrap()
    }

    pub fn get(&self, col: DBCol, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let value = self.db.get_cf(&self.cf_handle(col), key)?;
        value.map(|v| decrypt(&self.cipher, &v)).transpose()
    }

    pub fn iter_range(
        &self,
        col: DBCol,
        start: &[u8],
        end: &[u8],
    ) -> impl Iterator<Item = anyhow::Result<(Box<[u8]>, Vec<u8>)>> + '_ {
        let iter_mode = rocksdb::IteratorMode::From(start, rocksdb::Direction::Forward);
        let mut iter_opt = rocksdb::ReadOptions::default();
        iter_opt.set_iterate_upper_bound(end);
        let iter = self
            .db
            .iterator_cf_opt(&self.cf_handle(col), iter_opt, iter_mode);
        iter.map(move |result| {
            let (key, value) = result?;
            let value = decrypt(&self.cipher, &value)?;
            anyhow::Ok((key, value))
        })
    }

    pub fn update(self: &Arc<Self>) -> SecretDBUpdate {
        SecretDBUpdate {
            db: self.clone(),
            batch: rocksdb::WriteBatch::default(),
        }
    }

    fn get_cf_key_range(
        &self,
        col: DBCol,
    ) -> anyhow::Result<Option<std::ops::RangeInclusive<Box<[u8]>>>> {
        let range = {
            let mut iter = self
                .db
                .iterator_cf(self.cf_handle(col), IteratorMode::Start);
            let start = iter.next().transpose()?;
            iter.set_mode(IteratorMode::End);
            let end = iter.next().transpose()?;
            (start, end)
        };
        match range {
            (Some(start), Some(end)) => Ok(Some(start.0..=end.0)),
            (None, None) => Ok(None),
            _ => unreachable!(),
        }
    }
}

pub struct SecretDBUpdate {
    db: Arc<SecretDB>,
    batch: rocksdb::WriteBatch,
}

impl SecretDBUpdate {
    pub fn put(&mut self, col: DBCol, key: &[u8], value: &[u8]) {
        let value = encrypt(&self.db.cipher, value);
        self.batch.put_cf(&self.db.cf_handle(col), key, &value);
    }

    pub fn delete(&mut self, col: DBCol, key: &[u8]) {
        self.batch.delete_cf(&self.db.cf_handle(col), key);
    }

    pub fn delete_all(&mut self, col: DBCol) -> anyhow::Result<()> {
        let range = self.db.get_cf_key_range(col)?;
        if let Some(range) = range {
            self.batch
                .delete_range_cf(self.db.cf_handle(col), range.start(), range.end());
            self.batch.delete_cf(self.db.cf_handle(col), range.end());
        }
        Ok(())
    }

    pub fn commit(self) -> anyhow::Result<()> {
        self.db.db.write(self.batch)?;
        Ok(())
    }
}
