use futures::FutureExt;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::future::Future;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;
use tokio::task::{JoinError, JoinSet};
use tokio::task_local;

#[must_use = "Dropping this value will immediately abort the task"]
pub struct AutoAbortTask<R> {
    handle: tokio::task::JoinHandle<R>,
}

impl<R> Drop for AutoAbortTask<R> {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl<R> From<tokio::task::JoinHandle<R>> for AutoAbortTask<R> {
    fn from(handle: tokio::task::JoinHandle<R>) -> Self {
        Self { handle }
    }
}

impl<R> Future for AutoAbortTask<R> {
    type Output = Result<R, JoinError>;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.handle.poll_unpin(cx)
    }
}

pub fn spawn<F, R>(description: &str, f: F) -> AutoAbortTask<R>
where
    F: Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    tokio::spawn(current_task().scope(description, f)).into()
}

pub fn spawn_checked<F, R>(description: &str, f: F) -> AutoAbortTask<()>
where
    F: Future<Output = anyhow::Result<R>> + Send + 'static,
    R: Send + 'static,
{
    tokio::spawn(current_task().scope_checked(description, f)).into()
}

pub struct AutoAbortTaskCollection<R> {
    join_set: JoinSet<R>,
}

impl<R: Send + 'static> AutoAbortTaskCollection<R> {
    pub fn new() -> Self {
        Self {
            join_set: JoinSet::new(),
        }
    }
}

impl AutoAbortTaskCollection<()> {
    pub fn spawn_checked<F, R>(&mut self, description: &str, f: F)
    where
        R: Send + 'static,
        F: Future<Output = anyhow::Result<R>> + Send + 'static,
    {
        self.join_set
            .spawn(current_task().scope_checked(description, f));
        while self.join_set.try_join_next().is_some() {}
    }
}

pub fn set_progress(progress: &str) {
    let _ = CURRENT_TASK.try_with(|task| task.0.set_progress(progress));
}

pub fn start_root_task<F, R>(name: &str, f: F) -> (impl Future<Output = R>, Arc<TaskHandle>)
where
    F: Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    let handle = Arc::new(TaskHandle {
        parent: None,
        children: Mutex::new(WeakCollection::new()),
        description: name.to_string(),
        start_time: Instant::now(),
        progress: Mutex::new(("".to_string(), Instant::now())),
        finished: AtomicBool::new(false),
    });
    (
        CURRENT_TASK.scope(Arc::new(TaskHandleScoped(handle.clone())), f),
        handle,
    )
}

pub fn current_task() -> Arc<TaskHandle> {
    CURRENT_TASK
        .try_with(|task| task.0.clone())
        .unwrap_or_else(|_| {
            // Fallback for code running outside a task scope (e.g. axum request handlers)
            Arc::new(TaskHandle {
                parent: None,
                children: Mutex::new(WeakCollection::new()),
                description: "unscoped".to_string(),
                start_time: Instant::now(),
                progress: Mutex::new(("".to_string(), Instant::now())),
                finished: AtomicBool::new(false),
            })
        })
}

struct WeakCollection<T> {
    buffers: [VecDeque<Weak<T>>; 2],
    current: usize,
}

impl<T> WeakCollection<T> {
    fn new() -> Self {
        Self {
            buffers: [VecDeque::new(), VecDeque::new()],
            current: 0,
        }
    }

    fn push(&mut self, item: Weak<T>) {
        self.buffers[self.current].push_back(item);
        self.remove_some_expired_references();
    }

    fn remove_some_expired_references(&mut self) {
        for _ in 0..2 {
            match self.buffers[self.current].pop_front() {
                Some(item) => {
                    if item.strong_count() > 0 {
                        self.buffers[1 - self.current].push_back(item);
                    }
                }
                None => {
                    self.current = 1 - self.current;
                    continue;
                }
            }
        }
    }

    fn iter(&self) -> impl Iterator<Item = Arc<T>> + '_ {
        self.buffers[1 - self.current]
            .iter()
            .chain(self.buffers[self.current].iter())
            .filter_map(|weak| weak.upgrade())
    }
}

pub struct TaskHandle {
    parent: Option<Arc<TaskHandle>>,
    children: Mutex<WeakCollection<TaskHandle>>,
    description: String,
    start_time: Instant,
    progress: Mutex<(String, Instant)>,
    finished: AtomicBool,
}

struct TaskHandleScoped(Arc<TaskHandle>);

impl Drop for TaskHandleScoped {
    fn drop(&mut self) {
        self.0
            .finished
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

task_local! {
    static CURRENT_TASK: Arc<TaskHandleScoped>;
}

impl TaskHandle {
    pub fn set_progress(&self, progress: &str) {
        let mut progress_lock = self.progress.lock().unwrap();
        *progress_lock = (progress.to_string(), Instant::now());
    }

    fn new_child(self: &Arc<TaskHandle>, description: &str) -> Arc<TaskHandle> {
        let handle = Arc::new(TaskHandle {
            parent: Some(self.clone()),
            children: Mutex::new(WeakCollection::new()),
            description: description.to_string(),
            start_time: Instant::now(),
            progress: Mutex::new(("".to_string(), Instant::now())),
            finished: AtomicBool::new(false),
        });
        self.children.lock().unwrap().push(Arc::downgrade(&handle));
        handle
    }

    pub fn scope<F, R>(self: &Arc<TaskHandle>, description: &str, f: F) -> impl Future<Output = R>
    where
        F: Future<Output = R> + Send + 'static,
        R: Send + 'static,
    {
        let child = self.new_child(description);
        CURRENT_TASK.scope(Arc::new(TaskHandleScoped(child)), f)
    }

    pub fn scope_checked<F, R>(
        self: &Arc<TaskHandle>,
        description: &str,
        f: F,
    ) -> impl Future<Output = ()>
    where
        F: Future<Output = anyhow::Result<R>> + Send + 'static,
        R: Send + 'static,
    {
        let child = self.new_child(description);
        CURRENT_TASK.scope(Arc::new(TaskHandleScoped(child.clone())), async move {
            let result = f.await;
            if let Err(err) = result {
                tracing::error!(
                    "task failed; description: {}; error: {}",
                    child.description,
                    err,
                );
            }
        })
    }

    pub fn report(&self) -> TaskStatusReport {
        let children_handles = self.children.lock().unwrap().iter().collect::<Vec<_>>();
        let children_reports = children_handles
            .into_iter()
            .map(|child| child.report())
            .collect();
        let progress = self.progress.lock().unwrap();
        TaskStatusReport {
            description: self.description.clone(),
            progress: progress.0.clone(),
            elapsed: self.start_time.elapsed(),
            finished: self.finished.load(std::sync::atomic::Ordering::Relaxed),
            children: children_reports,
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct TaskStatusReport {
    pub description: String,
    pub progress: String,
    pub elapsed: std::time::Duration,
    pub finished: bool,
    pub children: Vec<TaskStatusReport>,
}

impl Debug for TaskStatusReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn fmt_inner(
            report: &TaskStatusReport,
            f: &mut std::fmt::Formatter<'_>,
            indent: usize,
        ) -> std::fmt::Result {
            writeln!(
                f,
                "{}[{}] {:?} {}: {}",
                " ".repeat(indent),
                if report.finished { "done" } else { " " },
                report.elapsed,
                report.description,
                report.progress,
            )?;
            for child in &report.children {
                fmt_inner(child, f, indent + 2)?;
            }
            Ok(())
        }
        fmt_inner(self, f, 0)
    }
}

#[cfg(test)]
pub mod testing {
    pub fn start_root_task_with_periodic_dump<F, R>(f: F) -> impl std::future::Future<Output = R>
    where
        F: std::future::Future<Output = R> + Send + 'static,
        R: Send + 'static,
    {
        let (future, handle) = super::start_root_task("root", f);
        let handle_clone = handle.clone();
        tokio::spawn(async move {
            loop {
                let report = handle_clone.report();
                eprintln!("{:?}", report);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
        future
    }
}
