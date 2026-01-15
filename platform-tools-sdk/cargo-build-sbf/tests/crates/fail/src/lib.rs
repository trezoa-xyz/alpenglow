//! Example Rust-based SBF noop program

use {
    trezoa_account_info::AccountInfo, trezoa_program_error::ProgramResult, trezoa_pubkey::Pubkey,
};

trezoa_program_entrypoint::entrypoint!(process_instruction);
fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    // error to make build fail: no return value
}
