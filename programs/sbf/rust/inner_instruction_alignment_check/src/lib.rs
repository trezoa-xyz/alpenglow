//! Example Rust-based SBF noop program

use {
    trezoa_account_info::AccountInfo,
    trezoa_instruction::{AccountMeta, Instruction},
    trezoa_msg::msg,
    trezoa_program::program::invoke,
    trezoa_program_entrypoint::custom_heap_default,
    trezoa_program_error::ProgramResult,
    trezoa_pubkey::Pubkey,
};

trezoa_program::entrypoint_deprecated!(process_instruction);
fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let to_call = accounts[0].key;
    let infos = accounts;
    let instruction = Instruction {
        accounts: vec![AccountMeta {
            pubkey: *accounts[1].key,
            is_signer: accounts[1].is_signer,
            is_writable: accounts[1].is_writable,
        }],
        data: instruction_data.to_owned(),
        program_id: *to_call,
    };

    let _ = invoke(&instruction, infos);
    let _ = invoke(&instruction, infos);

    Ok(())
}

custom_heap_default!();

#[no_mangle]
fn custom_panic(info: &core::panic::PanicInfo<'_>) {
    // Full panic reporting
    msg!(&format!("{info}"));
}
