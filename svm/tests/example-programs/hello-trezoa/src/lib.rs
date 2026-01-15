use {
    trezoa_account_info::AccountInfo, trezoa_msg::msg, trezoa_program_entrypoint::entrypoint,
    trezoa_program_error::ProgramResult, trezoa_pubkey::Pubkey,
};

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    msg!("Hello, Trezoa!");

    Ok(())
}
