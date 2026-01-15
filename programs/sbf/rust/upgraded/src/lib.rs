//! Example Rust-based SBF upgraded program

use {
    trezoa_account_info::AccountInfo, trezoa_msg::msg, trezoa_program_error::ProgramResult,
    trezoa_pubkey::Pubkey, trezoa_sysvar::clock,
};

trezoa_program_entrypoint::entrypoint_no_alloc!(process_instruction);
fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    msg!("Upgraded program");
    assert_eq!(accounts.len(), 1);
    assert_eq!(*accounts[0].key, clock::id());
    Err(43.into())
}
