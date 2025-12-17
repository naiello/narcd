use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const LOG_CHAN_SIZE: usize = 2048;

#[derive(Deserialize)]
pub struct LoggingConfig {
    pub dir: PathBuf,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            dir: "/var/log/narcd".into(),
        }
    }
}

pub trait EventLogger<E: Serialize>: Send + Clone {
    fn log_event(&self, event: E) -> impl std::future::Future<Output = Result<()>> + Send;
}

pub struct FileLogger<E: Serialize> {
    tx: mpsc::Sender<E>,
    _writer: Arc<JoinHandle<()>>,
}

impl<E: Serialize> Clone for FileLogger<E> {
    fn clone(&self) -> Self {
        FileLogger {
            tx: self.tx.clone(),
            _writer: self._writer.clone(),
        }
    }
}

impl<E: Serialize + Send + Sync + 'static> FileLogger<E> {
    pub async fn new(log_dir: impl AsRef<Path>, filename: &str) -> Result<Self> {
        let filename = log_dir.as_ref().join(filename);
        let mut log_file = tokio::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(filename)
            .await?;
        let (tx, mut rx) = mpsc::channel::<E>(LOG_CHAN_SIZE);

        let writer = tokio::spawn(async move {
            loop {
                if let Some(event) = rx.recv().await {
                    match serde_json::to_vec(&event) {
                        Ok(event) => {
                            log_file.write_all(&event).await.ok();
                            log_file.write_all(b"\n").await.ok();
                        }
                        Err(e) => log::error!("failed to serialize event: {:?}", e),
                    }
                } else {
                    log::error!("bad recv");
                }
            }
        });
        let _writer = Arc::new(writer);

        Ok(FileLogger { tx, _writer })
    }
}

impl<E: Serialize + Send + Sync + 'static> EventLogger<E> for FileLogger<E> {
    async fn log_event(&self, event: E) -> Result<()> {
        Ok(self.tx.send(event).await?)
    }
}
