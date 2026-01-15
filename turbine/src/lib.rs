#![allow(clippy::arithmetic_side_effects)]

#[cfg(feature = "trezoa-unstable-api")]
mod addr_cache;

#[cfg(feature = "trezoa-unstable-api")]
pub mod broadcast_stage;

#[cfg(feature = "trezoa-unstable-api")]
pub mod cluster_nodes;

#[cfg(feature = "trezoa-unstable-api")]
pub mod quic_endpoint;

#[cfg(feature = "trezoa-unstable-api")]
pub mod retransmit_stage;

#[cfg(feature = "trezoa-unstable-api")]
pub mod sigverify_shreds;

#[cfg(feature = "trezoa-unstable-api")]
pub mod xdp;

#[cfg(feature = "trezoa-unstable-api")]
#[macro_use]
extern crate log;

#[cfg(feature = "trezoa-unstable-api")]
#[macro_use]
extern crate trezoa_metrics;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;
