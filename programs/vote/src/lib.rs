#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]

pub mod vote_processor;
pub mod vote_state;

#[cfg_attr(feature = "metrics", macro_use)]
#[cfg(feature = "metrics")]
extern crate trezoa_metrics;

#[cfg(feature = "frozen-abi")]
extern crate trezoa_frozen_abi_macro;

pub use trezoa_vote_interface::{
    authorized_voters, error as vote_error, instruction as vote_instruction,
    program::{check_id, id},
};
