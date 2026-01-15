#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]

pub use trezoa_sbpf;
pub mod cpi;
pub mod execution_budget;
pub mod invoke_context;
pub mod loaded_programs;
pub mod mem_pool;
pub mod memory;
pub mod serialization;
pub mod stable_log;
pub mod sysvar_cache;

// re-exports for macros
pub mod __private {
    pub use {
        trezoa_account::ReadableAccount, trezoa_hash::Hash,
        trezoa_instruction::error::InstructionError, trezoa_rent::Rent,
        trezoa_transaction_context::TransactionContext,
    };
}
