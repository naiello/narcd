use crate::events::Event;
use anyhow::Result;
use serde::Deserialize;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const LOG_CHAN_SIZE: usize = 2048;

#[derive(Deserialize)]
pub struct LoggingConfig {
    pub filename: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            filename: "/var/log/narcd/events.log".to_string(),
        }
    }
}

pub trait EventLogger: Send + Clone {
    fn log_event(&self, event: Event) -> impl std::future::Future<Output = Result<()>> + Send;
}

#[derive(Clone)]
pub struct FileLogger {
    tx: mpsc::Sender<Event>,
    _writer: Arc<JoinHandle<()>>,
}

impl FileLogger {
    pub async fn new(filename: &str) -> Result<Self> {
        let mut log_file = tokio::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(filename)
            .await?;
        let (tx, mut rx) = mpsc::channel::<Event>(LOG_CHAN_SIZE);

        let writer = tokio::spawn(async move {
            loop {
                if let Some(event) = rx.recv().await {
                    match serde_json::to_vec(&event) {
                        Ok(event) => {
                            log_file.write(&event).await.ok();
                            log_file.write(b"\n").await.ok();
                        }
                        Err(e) => log::error!("failed to serialize event {:?}: {:?}", event, e),
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

impl EventLogger for FileLogger {
    async fn log_event(&self, event: Event) -> Result<()> {
        Ok(self.tx.send(event).await?)
    }
}
