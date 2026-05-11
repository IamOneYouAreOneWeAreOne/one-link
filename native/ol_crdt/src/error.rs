use thiserror::Error;

pub type Result<T> = std::result::Result<T, CrdtError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CrdtError {
    #[error("vector clock comparison incompatible (concurrent histories)")]
    Concurrent,

    #[error("invalid encoding: {0}")]
    InvalidEncoding(&'static str),
}
