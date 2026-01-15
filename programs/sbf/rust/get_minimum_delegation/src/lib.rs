//! Example/test program to get the minimum stake delegation via the helper function

#![allow(unreachable_code)]

use {
    trezoa_account_info::AccountInfo, trezoa_msg::msg, trezoa_program_error::ProgramResult,
    trezoa_pubkey::Pubkey, trezoa_stake_interface as stake,
};

trezoa_program_entrypoint::entrypoint_no_alloc!(process_instruction);
fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let minimum_delegation = stake::tools::get_minimum_delegation()?;
    msg!(
        "The minimum stake delegation is {} lamports",
        minimum_delegation
    );
    Ok(())
}
