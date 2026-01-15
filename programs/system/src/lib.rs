#![allow(clippy::arithmetic_side_effects)]
pub mod system_instruction;
pub mod system_processor;

use trezoa_sdk_ids::system_program;
pub use {
    trezoa_nonce_account::{get_system_account_kind, SystemAccountKind},
    system_program::id,
};
