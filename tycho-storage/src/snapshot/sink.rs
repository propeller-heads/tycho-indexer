use std::path::PathBuf;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncWriteExt, BufWriter};

/// Returned by a successfully finalized sink.
pub struct SinkResult {
    pub size_bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Async write-only byte sink that tracks position and accumulates SHA-256.
#[async_trait]
pub trait SnapshotSink: Send {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), SinkError>;
    fn position(&self) -> u64;
    /// Seals the sink and returns size + digest. Consumes via `Box<Self>` for object-safety.
    async fn finalize(self: Box<Self>) -> Result<SinkResult, SinkError>;
}

/// Creates sinks by key without exposing raw config to callers.
#[async_trait]
pub trait SinkFactory: Send + Sync {
    async fn create_sink(&self, key: &str) -> Result<Box<dyn SnapshotSink>, SinkError>;
}

// ─────────────────────────── FileSink ────────────────────────────────────────

pub struct FileSink {
    writer: BufWriter<tokio::fs::File>,
    hasher: Sha256,
    position: u64,
}

impl FileSink {
    pub async fn create(path: PathBuf) -> Result<Self, SinkError> {
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .await?;
        Ok(Self { writer: BufWriter::new(file), hasher: Sha256::new(), position: 0 })
    }
}

#[async_trait]
impl SnapshotSink for FileSink {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), SinkError> {
        self.hasher.update(buf);
        self.position += buf.len() as u64;
        self.writer.write_all(buf).await?;
        Ok(())
    }

    fn position(&self) -> u64 {
        self.position
    }

    async fn finalize(mut self: Box<Self>) -> Result<SinkResult, SinkError> {
        self.writer.flush().await?;
        let sha256 = self.hasher.finalize().into();
        Ok(SinkResult { size_bytes: self.position, sha256 })
    }
}

// ─────────────────────────── FileSinkFactory ─────────────────────────────────

pub struct FileSinkFactory {
    base_dir: PathBuf,
}

impl FileSinkFactory {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }
}

#[async_trait]
impl SinkFactory for FileSinkFactory {
    async fn create_sink(&self, key: &str) -> Result<Box<dyn SnapshotSink>, SinkError> {
        let path = self.base_dir.join(key);
        Ok(Box::new(FileSink::create(path).await?))
    }
}

// ─────────────────────────── Tests ───────────────────────────────────────────

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn file_sink_write_finalize_verifies_size_and_sha256() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("snapshot.bin");
        let data = b"hello, snapshot!";
        let expected_sha256: [u8; 32] = Sha256::digest(data).into();

        let mut sink = FileSink::create(path).await.unwrap();
        sink.write_all(data).await.unwrap();
        let result = Box::new(sink).finalize().await.unwrap();

        assert_eq!(result.size_bytes, data.len() as u64);
        assert_eq!(result.sha256, expected_sha256);
    }

    #[tokio::test]
    async fn file_sink_satisfies_boxed_dyn_snapshot_sink() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("snapshot_dyn.bin");
        let data = b"boxed sink test";

        let mut sink: Box<dyn SnapshotSink> = Box::new(FileSink::create(path).await.unwrap());
        sink.write_all(data).await.unwrap();
        let result = sink.finalize().await.unwrap();

        assert_eq!(result.size_bytes, data.len() as u64);
    }
}
