//! config for staking
//!  carries variables that the stake program cares about
#[deprecated(
    since = "1.8.0",
    note = "Please use `trezoa_stake_interface::config` instead"
)]
pub use trezoa_stake_interface::config::*;
use {
    bincode::{deserialize, serialize},
    trezoa_account::{Account, AccountSharedData, ReadableAccount, WritableAccount},
    trezoa_config_interface::state::{get_config_data, ConfigKeys},
    trezoa_genesis_config::GenesisConfig,
    trezoa_pubkey::Pubkey,
    trezoa_transaction_context::BorrowedInstructionAccount,
};

#[allow(deprecated)]
fn create_config_account(
    keys: Vec<(Pubkey, bool)>,
    config_data: &Config,
    lamports: u64,
) -> AccountSharedData {
    let mut data = serialize(&ConfigKeys { keys }).unwrap();
    data.extend_from_slice(&serialize(config_data).unwrap());
    AccountSharedData::from(Account {
        lamports,
        data,
        owner: trezoa_sdk_ids::config::id(),
        ..Account::default()
    })
}

#[allow(deprecated)]
pub fn from(account: &BorrowedInstructionAccount) -> Option<Config> {
    get_config_data(account.get_data())
        .ok()
        .and_then(|data| deserialize(data).ok())
}

#[allow(deprecated)]
pub fn create_account(lamports: u64, config: &Config) -> AccountSharedData {
    create_config_account(vec![], config, lamports)
}

#[allow(deprecated)]
pub fn add_genesis_account(genesis_config: &mut GenesisConfig) -> u64 {
    let mut account = create_config_account(vec![], &Config::default(), 0);
    let lamports = std::cmp::max(genesis_config.rent.minimum_balance(account.data().len()), 1);

    account.set_lamports(lamports);

    genesis_config.add_account(trezoa_stake_interface::config::id(), account);

    lamports
}
