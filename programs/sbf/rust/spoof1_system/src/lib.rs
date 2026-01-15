#![allow(clippy::arithmetic_side_effects)]

use {
    trezoa_account_info::AccountInfo, trezoa_program_error::ProgramResult, trezoa_pubkey::Pubkey,
};

trezoa_program_entrypoint::entrypoint_no_alloc!(process_instruction);
fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let from = &accounts[0];
    let to = &accounts[1];

    let to_balance = to.lamports();
    **to.lamports.borrow_mut() = to_balance + from.lamports();
    **from.lamports.borrow_mut() = 0u64;

    Ok(())
}
