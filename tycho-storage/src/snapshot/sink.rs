use std::path::PathBuf;

use async_trait::async_trait;
#[cfg(feature = "s3")]
use aws_sdk_s3::{
    types::{CompletedMultipartUpload, CompletedPart},
    Client,
};
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
    #[cfg(feature = "s3")]
    #[error("Failed to create multipart upload: {0}")]
    UploadCreateFailed(String),
    #[cfg(feature = "s3")]
    #[error("Part {part} upload failed: {reason}")]
    PartFailed { part: i32, reason: String },
    #[cfg(feature = "s3")]
    #[error("Failed to complete multipart upload: {0}")]
    CompleteFailed(String),
    #[cfg(feature = "s3")]
    #[error("Failed to abort multipart upload: {0}")]
    AbortFailed(String),
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

// ─────────────────────────── S3Ops (internal trait) ──────────────────────────

#[cfg(feature = "s3")]
pub const DEFAULT_PART_THRESHOLD: usize = 64 * 1024 * 1024;

#[cfg(feature = "s3")]
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub(crate) trait S3Ops: Send + Sync {
    async fn create_multipart_upload(&self, bucket: &str, key: &str) -> Result<String, SinkError>;

    async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        data: Vec<u8>,
    ) -> Result<CompletedPart, SinkError>;

    async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: Vec<CompletedPart>,
    ) -> Result<(), SinkError>;

    async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), SinkError>;
}

// ─────────────────────────── AwsS3Ops ────────────────────────────────────────

#[cfg(feature = "s3")]
pub(crate) struct AwsS3Ops {
    client: Client,
}

#[cfg(feature = "s3")]
impl AwsS3Ops {
    pub(crate) fn new(client: Client) -> Self {
        Self { client }
    }
}

#[cfg(feature = "s3")]
#[async_trait]
impl S3Ops for AwsS3Ops {
    async fn create_multipart_upload(&self, bucket: &str, key: &str) -> Result<String, SinkError> {
        let resp = self
            .client
            .create_multipart_upload()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| SinkError::UploadCreateFailed(e.to_string()))?;
        resp.upload_id()
            .map(str::to_string)
            .ok_or_else(|| SinkError::UploadCreateFailed("missing upload_id in response".into()))
    }

    async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        data: Vec<u8>,
    ) -> Result<CompletedPart, SinkError> {
        let body = aws_sdk_s3::primitives::ByteStream::from(data);
        let resp = self
            .client
            .upload_part()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(body)
            .send()
            .await
            .map_err(|e| SinkError::PartFailed { part: part_number, reason: e.to_string() })?;
        let e_tag = resp.e_tag().map(str::to_string);
        Ok(CompletedPart::builder()
            .set_e_tag(e_tag)
            .part_number(part_number)
            .build())
    }

    async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: Vec<CompletedPart>,
    ) -> Result<(), SinkError> {
        let upload = CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();
        self.client
            .complete_multipart_upload()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(upload)
            .send()
            .await
            .map_err(|e| SinkError::CompleteFailed(e.to_string()))?;
        Ok(())
    }

    async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), SinkError> {
        self.client
            .abort_multipart_upload()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
            .map_err(|e| SinkError::AbortFailed(e.to_string()))?;
        Ok(())
    }
}

// ─────────────────────────── S3Sink ──────────────────────────────────────────

#[cfg(feature = "s3")]
pub struct S3Sink {
    ops: Box<dyn S3Ops>,
    bucket: String,
    key: String,
    upload_id: String,
    part_threshold: usize,
    buffer: Vec<u8>,
    completed_parts: Vec<CompletedPart>,
    part_number: i32,
    hasher: Sha256,
    position: u64,
}

#[cfg(feature = "s3")]
impl S3Sink {
    pub async fn create(
        client: Client,
        bucket: String,
        key: String,
        part_threshold: usize,
    ) -> Result<Self, SinkError> {
        Self::create_with_ops(Box::new(AwsS3Ops::new(client)), bucket, key, part_threshold).await
    }

    pub(crate) async fn create_with_ops(
        ops: Box<dyn S3Ops>,
        bucket: String,
        key: String,
        part_threshold: usize,
    ) -> Result<Self, SinkError> {
        let upload_id = ops
            .create_multipart_upload(&bucket, &key)
            .await?;
        Ok(Self {
            ops,
            bucket,
            key,
            upload_id,
            part_threshold,
            buffer: Vec::new(),
            completed_parts: Vec::new(),
            part_number: 0,
            hasher: Sha256::new(),
            position: 0,
        })
    }

    async fn flush_part(&mut self) -> Result<(), SinkError> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        self.part_number += 1;
        let data = std::mem::take(&mut self.buffer);
        match self
            .ops
            .upload_part(&self.bucket, &self.key, &self.upload_id, self.part_number, data)
            .await
        {
            Ok(part) => {
                self.completed_parts.push(part);
                Ok(())
            }
            Err(e) => {
                if let Err(abort_err) = self
                    .ops
                    .abort_multipart_upload(&self.bucket, &self.key, &self.upload_id)
                    .await
                {
                    tracing::warn!(error = %abort_err, "failed to abort multipart upload");
                }
                Err(e)
            }
        }
    }
}

#[cfg(feature = "s3")]
#[async_trait]
impl SnapshotSink for S3Sink {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), SinkError> {
        self.hasher.update(buf);
        self.position += buf.len() as u64;
        let mut remaining = buf;
        while !remaining.is_empty() {
            let space = self.part_threshold - self.buffer.len();
            let take = remaining.len().min(space);
            self.buffer
                .extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            if self.buffer.len() >= self.part_threshold {
                self.flush_part().await?;
            }
        }
        Ok(())
    }

    fn position(&self) -> u64 {
        self.position
    }

    async fn finalize(mut self: Box<Self>) -> Result<SinkResult, SinkError> {
        if self.buffer.is_empty() && self.completed_parts.is_empty() {
            let _ = self
                .ops
                .abort_multipart_upload(&self.bucket, &self.key, &self.upload_id)
                .await;
            return Err(SinkError::CompleteFailed("cannot finalize an empty upload".into()));
        }
        self.flush_part().await?;
        let sha256: [u8; 32] = self.hasher.finalize().into();
        let size_bytes = self.position;
        let parts = std::mem::take(&mut self.completed_parts);
        let complete_result = self
            .ops
            .complete_multipart_upload(&self.bucket, &self.key, &self.upload_id, parts)
            .await;
        if let Err(e) = complete_result {
            if let Err(abort_err) = self
                .ops
                .abort_multipart_upload(&self.bucket, &self.key, &self.upload_id)
                .await
            {
                tracing::warn!(error = %abort_err, "failed to abort multipart upload");
            }
            return Err(e);
        }
        Ok(SinkResult { size_bytes, sha256 })
    }
}

// ─────────────────────────── S3SinkFactory ───────────────────────────────────

#[cfg(feature = "s3")]
pub struct S3SinkFactory {
    client: Client,
    bucket: String,
    part_threshold: usize,
}

#[cfg(feature = "s3")]
impl S3SinkFactory {
    pub async fn from_env(bucket: String) -> Self {
        let config = aws_config::from_env().load().await;
        let client = Client::new(&config);
        Self { client, bucket, part_threshold: DEFAULT_PART_THRESHOLD }
    }

    pub fn with_client(client: Client, bucket: String, part_threshold: usize) -> Self {
        const MIN_PART_SIZE: usize = 5 * 1024 * 1024;
        assert!(
            part_threshold >= MIN_PART_SIZE,
            "part_threshold must be >= 5 MiB (S3 minimum part size)"
        );
        Self { client, bucket, part_threshold }
    }
}

#[cfg(feature = "s3")]
#[async_trait]
impl SinkFactory for S3SinkFactory {
    async fn create_sink(&self, key: &str) -> Result<Box<dyn SnapshotSink>, SinkError> {
        Ok(Box::new(
            S3Sink::create(
                self.client.clone(),
                self.bucket.clone(),
                key.to_string(),
                self.part_threshold,
            )
            .await?,
        ))
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

    #[cfg(all(test, feature = "s3"))]
    mod s3_tests {
        use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
        use testcontainers::runners::AsyncRunner;
        use testcontainers_modules::minio::MinIO;

        use super::*;

        fn make_s3_client(endpoint: &str) -> Client {
            let creds = Credentials::new("minioadmin", "minioadmin", None, None, "test");
            let config = aws_sdk_s3::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .endpoint_url(endpoint)
                .credentials_provider(creds)
                .region(Region::new("us-east-1"))
                .force_path_style(true)
                .build();
            Client::from_conf(config)
        }

        async fn create_bucket(client: &Client, bucket: &str) {
            client
                .create_bucket()
                .bucket(bucket)
                .send()
                .await
                .unwrap();
        }

        #[test]
        #[should_panic(expected = "part_threshold must be >= 5 MiB")]
        fn s3_sink_factory_with_client_rejects_sub_minimum_threshold() {
            let config = aws_sdk_s3::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new("us-east-1"))
                .build();
            S3SinkFactory::with_client(Client::from_conf(config), "bucket".to_string(), 100);
        }

        #[tokio::test]
        async fn s3_sink_finalize_empty_upload_aborts_and_returns_error() {
            let mut mock = MockS3Ops::new();
            mock.expect_create_multipart_upload()
                .returning(|_, _| Ok("test-upload-id".to_string()));
            mock.expect_abort_multipart_upload()
                .times(1)
                .returning(|_, _, _| Ok(()));

            let sink = S3Sink::create_with_ops(
                Box::new(mock),
                "bucket".to_string(),
                "key".to_string(),
                DEFAULT_PART_THRESHOLD,
            )
            .await
            .unwrap();

            let result = Box::new(sink).finalize().await;
            assert!(matches!(result, Err(SinkError::CompleteFailed(_))));
        }

        #[tokio::test]
        async fn s3_sink_write_all_chunks_large_input_into_multiple_parts() {
            let mut mock = MockS3Ops::new();
            mock.expect_create_multipart_upload()
                .returning(|_, _| Ok("test-upload-id".to_string()));
            mock.expect_upload_part()
                .times(2)
                .returning(|_, _, _, part_num, data| {
                    assert_eq!(data.len(), 5);
                    Ok(CompletedPart::builder()
                        .part_number(part_num)
                        .build())
                });
            mock.expect_complete_multipart_upload()
                .times(1)
                .returning(|_, _, _, parts| {
                    assert_eq!(parts.len(), 2);
                    Ok(())
                });

            let mut sink = S3Sink::create_with_ops(
                Box::new(mock),
                "bucket".to_string(),
                "key".to_string(),
                5, // 5-byte threshold
            )
            .await
            .unwrap();

            // Single write_all of 10 bytes must be chunked into 2 × 5-byte parts.
            sink.write_all(b"0123456789")
                .await
                .unwrap();
            let result = Box::new(sink).finalize().await.unwrap();
            assert_eq!(result.size_bytes, 10);
        }

        #[tokio::test]
        async fn s3_sink_upload_part_failure_calls_abort_and_returns_part_failed() {
            let mut mock = MockS3Ops::new();
            mock.expect_create_multipart_upload()
                .returning(|_, _| Ok("test-upload-id".to_string()));
            mock.expect_upload_part()
                .returning(|_, _, _, part_num, _| {
                    Err(SinkError::PartFailed {
                        part: part_num,
                        reason: "network error".to_string(),
                    })
                });
            mock.expect_abort_multipart_upload()
                .times(1)
                .returning(|_, _, _| Ok(()));

            let mut sink = S3Sink::create_with_ops(
                Box::new(mock),
                "test-bucket".to_string(),
                "test-key".to_string(),
                5, // small threshold to trigger flush
            )
            .await
            .unwrap();

            let result = sink.write_all(b"hello world!").await;
            assert!(matches!(result, Err(SinkError::PartFailed { part: 1, .. })));
        }

        #[tokio::test]
        async fn s3_sink_multipart_upload_completes_and_data_matches() {
            let minio = MinIO::default().start().await.unwrap();
            let port = minio
                .get_host_port_ipv4(9000)
                .await
                .unwrap();
            let endpoint = format!("http://127.0.0.1:{port}");
            let client = make_s3_client(&endpoint);

            let bucket = "test-bucket";
            let key = "test/snapshot.bin";
            create_bucket(&client, bucket).await;

            let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
            let expected_sha256: [u8; 32] = Sha256::digest(&data).into();

            let mut sink = S3Sink::create(
                client.clone(),
                bucket.to_string(),
                key.to_string(),
                DEFAULT_PART_THRESHOLD,
            )
            .await
            .unwrap();
            sink.write_all(&data).await.unwrap();
            let result = Box::new(sink).finalize().await.unwrap();

            assert_eq!(result.size_bytes, data.len() as u64);
            assert_eq!(result.sha256, expected_sha256);

            let resp = client
                .get_object()
                .bucket(bucket)
                .key(key)
                .send()
                .await
                .unwrap();
            let stored = resp
                .body
                .collect()
                .await
                .unwrap()
                .into_bytes();
            assert_eq!(stored.as_ref(), data.as_slice());
        }

        #[tokio::test]
        async fn s3_sink_satisfies_boxed_dyn_snapshot_sink() {
            let minio = MinIO::default().start().await.unwrap();
            let port = minio
                .get_host_port_ipv4(9000)
                .await
                .unwrap();
            let endpoint = format!("http://127.0.0.1:{port}");
            let client = make_s3_client(&endpoint);

            let bucket = "test-bucket-dyn";
            let key = "dyn-test.bin";
            create_bucket(&client, bucket).await;

            let data = b"boxed s3 sink test";
            let sink =
                S3Sink::create(client, bucket.to_string(), key.to_string(), DEFAULT_PART_THRESHOLD)
                    .await
                    .unwrap();
            let mut sink: Box<dyn SnapshotSink> = Box::new(sink);
            sink.write_all(data).await.unwrap();
            let result = sink.finalize().await.unwrap();

            assert_eq!(result.size_bytes, data.len() as u64);
        }
    }
}
