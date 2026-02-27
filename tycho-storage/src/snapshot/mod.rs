pub mod sink;

pub use sink::{FileSink, FileSinkFactory, SinkError, SinkFactory, SinkResult, SnapshotSink};
#[cfg(feature = "s3")]
pub use sink::{S3Sink, S3SinkFactory, DEFAULT_PART_THRESHOLD};
