//! Example Rust-based SBF program that tests rand behavior

#![allow(unreachable_code)]

use {
    trezoa_account_info::AccountInfo, trezoa_msg::msg, trezoa_program_error::ProgramResult,
    trezoa_pubkey::Pubkey,
};

trezoa_program_entrypoint::entrypoint_no_alloc!(process_instruction);
fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    msg!("rand");
    Ok(())
}
