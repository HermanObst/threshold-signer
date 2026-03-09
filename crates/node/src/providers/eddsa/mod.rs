pub mod key_generation;
pub mod sign;

use crate::network::MeshNetworkClient;
use std::sync::Arc;
use threshold_signatures::frost::eddsa::KeygenOutput;

pub struct EddsaProvider {
    pub client: Arc<MeshNetworkClient>,
    pub threshold: usize,
    pub keyshare: Option<KeygenOutput>,
}
