//! Example/test program to trigger vm error by dividing by zero

#![feature(asm_experimental_arch)]

use {
    trezoa_account_info::AccountInfo, trezoa_program_error::ProgramResult, trezoa_pubkey::Pubkey,
    std::arch::asm,
};

trezoa_program_entrypoint::entrypoint_no_alloc!(process_instruction);
fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    unsafe {
        asm!(
            "
            mov64 r0, 0
            mov64 r1, 0
            div64 r0, r1
        "
        );
    }
    Ok(())
}
