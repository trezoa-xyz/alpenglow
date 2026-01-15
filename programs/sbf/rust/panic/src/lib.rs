//! Example Rust-based SBF program that panics

#[cfg(all(feature = "custom-panic", target_os = "trezoa"))]
#[no_mangle]
fn custom_panic(info: &core::panic::PanicInfo<'_>) {
    // Note: Full panic reporting is included here for testing purposes
    trezoa_msg::msg!("program custom panic enabled");
    trezoa_msg::msg!(&format!("{info}"));
}

use {
    trezoa_account_info::AccountInfo, trezoa_program_error::ProgramResult, trezoa_pubkey::Pubkey,
};

trezoa_program_entrypoint::entrypoint_no_alloc!(process_instruction);
fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    assert_eq!(1, 2);
    Ok(())
}
