// Skeleton created by sdk-kit 0.3.0; owned by this repository (edit freely).
//! # grow-casdoor
//!
//! Rust SDK for [Casdoor](https://grow-codes-packages.github.io/casdoor/) by Grow Codes.
//!
//! ```no_run
//! # async fn demo() -> grow_casdoor::Result<()> {
//! use grow_casdoor::{CasdoorClient, CasdoorConfig};
//!
//! let client = CasdoorClient::new(CasdoorConfig::from_env()?)?;
//! let health = client.health().await?;
//! println!("healthy: {}", health.healthy);
//! client.close().await;
//! # Ok(())
//! # }
//! ```
//!
//! Features: `blocking` (a blocking client), `testing` (in-memory fakes and the conformance
//! runner)
//! .
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod core;

pub mod casdoor;
mod client;
mod config;

#[cfg(feature = "blocking")]
#[cfg_attr(docsrs, doc(cfg(feature = "blocking")))]
pub mod blocking;

#[cfg(feature = "testing")]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing;

pub use crate::core::{Error, ErrorCode, HealthStatus, Result, RetryPolicy, Secret};

pub use crate::config::{DEFAULT_SCOPE, DEFAULT_URL};

pub use crate::casdoor::{pkce_challenge, random_state, Pkce, TokenSet};
pub use crate::client::{CasdoorClient, SignInInput};

pub use crate::config::CasdoorConfig;

pub use crate::config::CasdoorConfigBuilder;

/// Service-prefixed alias of [`Error`].
pub type CasdoorError = Error;
