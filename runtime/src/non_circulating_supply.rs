use {
    crate::bank::Bank,
    log::*,
    trezoa_account::ReadableAccount,
    trezoa_accounts_db::accounts_index::{AccountIndex, IndexKey, ScanConfig, ScanResult},
    trezoa_pubkey::Pubkey,
    trezoa_stake_interface::{self as stake, state::StakeStateV2},
    trezoa_stake_program::stake_state,
    std::collections::HashSet,
};

pub struct NonCirculatingSupply {
    pub lamports: u64,
    pub accounts: Vec<Pubkey>,
}

pub fn calculate_non_circulating_supply(bank: &Bank) -> ScanResult<NonCirculatingSupply> {
    debug!("Updating Bank supply, epoch: {}", bank.epoch());
    let mut non_circulating_accounts_set: HashSet<Pubkey> = HashSet::new();

    for key in non_circulating_accounts() {
        non_circulating_accounts_set.insert(key);
    }
    let withdraw_authority_list = withdraw_authority();

    let clock = bank.clock();
    let config = &ScanConfig::default();
    let stake_accounts = if bank
        .rc
        .accounts
        .accounts_db
        .account_indexes
        .contains(&AccountIndex::ProgramId)
    {
        bank.get_filtered_indexed_accounts(
            &IndexKey::ProgramId(stake::program::id()),
            // The program-id account index checks for Account owner on inclusion. However, due to
            // the current AccountsDb implementation, an account may remain in storage as a
            // zero-lamport Account::Default() after being wiped and reinitialized in later
            // updates. We include the redundant filter here to avoid returning these accounts.
            |account| account.owner() == &stake::program::id(),
            config,
            None,
        )?
    } else {
        bank.get_program_accounts(&stake::program::id(), config)?
    };

    for (pubkey, account) in stake_accounts.iter() {
        let stake_account = stake_state::from(account).unwrap_or_default();
        match stake_account {
            StakeStateV2::Initialized(meta) => {
                if meta.lockup.is_in_force(&clock, None)
                    || withdraw_authority_list.contains(&meta.authorized.withdrawer)
                {
                    non_circulating_accounts_set.insert(*pubkey);
                }
            }
            StakeStateV2::Stake(meta, _stake, _stake_flags) => {
                if meta.lockup.is_in_force(&clock, None)
                    || withdraw_authority_list.contains(&meta.authorized.withdrawer)
                {
                    non_circulating_accounts_set.insert(*pubkey);
                }
            }
            _ => {}
        }
    }

    let lamports = non_circulating_accounts_set
        .iter()
        .map(|pubkey| bank.get_balance(pubkey))
        .sum();

    Ok(NonCirculatingSupply {
        lamports,
        accounts: non_circulating_accounts_set.into_iter().collect(),
    })
}

// Mainnet-beta accounts that should be considered non-circulating
pub fn non_circulating_accounts() -> Vec<Pubkey> {
    [
        trezoa_pubkey::pubkey!("9huDUZfxoJ7wGMTffUE7vh1xePqef7gyrLJu9NApncqA"),
        trezoa_pubkey::pubkey!("GK2zqSsXLA2rwVZk347RYhh6jJpRsCA69FjLW93ZGi3B"),
        trezoa_pubkey::pubkey!("CWeRmXme7LmbaUWTZWFLt6FMnpzLCHaQLuR2TdgFn4Lq"),
        trezoa_pubkey::pubkey!("HCV5dGFJXRrJ3jhDYA4DCeb9TEDTwGGYXtT3wHksu2Zr"),
        trezoa_pubkey::pubkey!("14FUT96s9swbmH7ZjpDvfEDywnAYy9zaNhv4xvezySGu"),
        trezoa_pubkey::pubkey!("HbZ5FfmKWNHC7uwk6TF1hVi6TCs7dtYfdjEcuPGgzFAg"),
        trezoa_pubkey::pubkey!("C7C8odR8oashR5Feyrq2tJKaXL18id1dSj2zbkDGL2C2"),
        trezoa_pubkey::pubkey!("Eyr9P5XsjK2NUKNCnfu39eqpGoiLFgVAv1LSQgMZCwiQ"),
        trezoa_pubkey::pubkey!("DE1bawNcRJB9rVm3buyMVfr8mBEoyyu73NBovf2oXJsJ"),
        trezoa_pubkey::pubkey!("CakcnaRDHka2gXyfbEd2d3xsvkJkqsLw2akB3zsN1D2S"),
        trezoa_pubkey::pubkey!("7Np41oeYqPefeNQEHSv1UDhYrehxin3NStELsSKCT4K2"),
        trezoa_pubkey::pubkey!("GdnSyH3YtwcxFvQrVVJMm1JhTS4QVX7MFsX56uJLUfiZ"),
        trezoa_pubkey::pubkey!("Mc5XB47H3DKJHym5RLa9mPzWv5snERsF3KNv5AauXK8"),
        trezoa_pubkey::pubkey!("7cvkjYAkUYs4W8XcXsca7cBrEGFeSUjeZmKoNBvEwyri"),
        trezoa_pubkey::pubkey!("AG3m2bAibcY8raMt4oXEGqRHwX4FWKPPJVjZxn1LySDX"),
        trezoa_pubkey::pubkey!("5XdtyEDREHJXXW1CTtCsVjJRjBapAwK78ZquzvnNVRrV"),
        trezoa_pubkey::pubkey!("6yKHERk8rsbmJxvMpPuwPs1ct3hRiP7xaJF2tvnGU6nK"),
        trezoa_pubkey::pubkey!("CHmdL15akDcJgBkY6BP3hzs98Dqr6wbdDC5p8odvtSbq"),
        trezoa_pubkey::pubkey!("FR84wZQy3Y3j2gWz6pgETUiUoJtreMEuWfbg6573UCj9"),
        trezoa_pubkey::pubkey!("5q54XjQ7vDx4y6KphPeE97LUNiYGtP55spjvXAWPGBuf"),
        trezoa_pubkey::pubkey!("3o6xgkJ9sTmDeQWyfj3sxwon18fXJB9PV5LDc8sfgR4a"),
        trezoa_pubkey::pubkey!("GumSE5HsMV5HCwBTv2D2D81yy9x17aDkvobkqAfTRgmo"),
        trezoa_pubkey::pubkey!("AzVV9ZZDxTgW4wWfJmsG6ytaHpQGSe1yz76Nyy84VbQF"),
        trezoa_pubkey::pubkey!("8CUUMKYNGxdgYio5CLHRHyzMEhhVRMcqefgE6dLqnVRK"),
        trezoa_pubkey::pubkey!("CQDYc4ET2mbFhVpgj41gXahL6Exn5ZoPcGAzSHuYxwmE"),
        trezoa_pubkey::pubkey!("5PLJZLJiRR9vf7d1JCCg7UuWjtyN9nkab9uok6TqSyuP"),
        trezoa_pubkey::pubkey!("7xJ9CLtEAcEShw9kW2gSoZkRWL566Dg12cvgzANJwbTr"),
        trezoa_pubkey::pubkey!("BuCEvc9ze8UoAQwwsQLy8d447C8sA4zeVtVpc6m5wQeS"),
        trezoa_pubkey::pubkey!("8ndGYFjav6NDXvzYcxs449Aub3AxYv4vYpk89zRDwgj7"),
        trezoa_pubkey::pubkey!("8W58E8JVJjH1jCy5CeHJQgvwFXTyAVyesuXRZGbcSUGG"),
        trezoa_pubkey::pubkey!("GNiz4Mq886bTNDT3pijGsu2gbw6it7sqrwncro45USeB"),
        trezoa_pubkey::pubkey!("GhsotwFMH6XUrRLJCxcx62h7748N2Uq8mf87hUGkmPhg"),
        trezoa_pubkey::pubkey!("Fgyh8EeYGZtbW8sS33YmNQnzx54WXPrJ5KWNPkCfWPot"),
        trezoa_pubkey::pubkey!("8UVjvYyoqP6sqcctTso3xpCdCfgTMiv3VRh7vraC2eJk"),
        trezoa_pubkey::pubkey!("BhvLngiqqKeZ8rpxch2uGjeCiC88zzewoWPRuoxpp1aS"),
        trezoa_pubkey::pubkey!("63DtkW7zuARcd185EmHAkfF44bDcC2SiTSEj2spLP3iA"),
        trezoa_pubkey::pubkey!("GvpCiTgq9dmEeojCDBivoLoZqc4AkbUDACpqPMwYLWKh"),
        trezoa_pubkey::pubkey!("7Y8smnoUrYKGGuDq2uaFKVxJYhojgg7DVixHyAtGTYEV"),
        trezoa_pubkey::pubkey!("DUS1KxwUhUyDKB4A81E8vdnTe3hSahd92Abtn9CXsEcj"),
        trezoa_pubkey::pubkey!("F9MWFw8cnYVwsRq8Am1PGfFL3cQUZV37mbGoxZftzLjN"),
        trezoa_pubkey::pubkey!("8vqrX3H2BYLaXVintse3gorPEM4TgTwTFZNN1Fm9TdYs"),
        trezoa_pubkey::pubkey!("CUageMFi49kzoDqtdU8NvQ4Bq3sbtJygjKDAXJ45nmAi"),
        trezoa_pubkey::pubkey!("5smrYwb1Hr2T8XMnvsqccTgXxuqQs14iuE8RbHFYf2Cf"),
        trezoa_pubkey::pubkey!("xQadXQiUTCCFhfHjvQx1hyJK6KVWr1w2fD6DT3cdwj7"),
        trezoa_pubkey::pubkey!("8DE8fqPfv1fp9DHyGyDFFaMjpopMgDeXspzoi9jpBJjC"),
        trezoa_pubkey::pubkey!("3itU5ME8L6FDqtMiRoUiT1F7PwbkTtHBbW51YWD5jtjm"),
        trezoa_pubkey::pubkey!("AsrYX4FeLXnZcrjcZmrASY2Eq1jvEeQfwxtNTxS5zojA"),
        trezoa_pubkey::pubkey!("8rT45mqpuDBR1vcnDc9kwP9DrZAXDR4ZeuKWw3u1gTGa"),
        trezoa_pubkey::pubkey!("nGME7HgBT6tAJN1f6YuCCngpqT5cvSTndZUVLjQ4jwA"),
        trezoa_pubkey::pubkey!("CzAHrrrHKx9Lxf6wdCMrsZkLvk74c7J2vGv8VYPUmY6v"),
        trezoa_pubkey::pubkey!("AzHQ8Bia1grVVbcGyci7wzueSWkgvu7YZVZ4B9rkL5P6"),
        trezoa_pubkey::pubkey!("FiWYY85b58zEEcPtxe3PuqzWPjqBJXqdwgZeqSBmT9Cn"),
        trezoa_pubkey::pubkey!("GpxpMVhrBBBEYbEJxdR62w3daWz444V7m6dxYDZKH77D"),
        trezoa_pubkey::pubkey!("3bTGcGB9F98XxnrBNftmmm48JGfPgi5sYxDEKiCjQYk3"),
        trezoa_pubkey::pubkey!("8pNBEppa1VcFAsx4Hzq9CpdXUXZjUXbvQwLX2K7QsCwb"),
        trezoa_pubkey::pubkey!("HKJgYGTTYYR2ZkfJKHbn58w676fKueQXmvbtpyvrSM3N"),
        trezoa_pubkey::pubkey!("3jnknRabs7G2V9dKhxd2KP85pNWXKXiedYnYxtySnQMs"),
        trezoa_pubkey::pubkey!("4sxwau4mdqZ8zEJsfryXq4QFYnMJSCp3HWuZQod8WU5k"),
        trezoa_pubkey::pubkey!("Fg12tB1tz8w6zJSQ4ZAGotWoCztdMJF9hqK8R11pakog"),
        trezoa_pubkey::pubkey!("GEWSkfWgHkpiLbeKaAnwvqnECGdRNf49at5nFccVey7c"),
        trezoa_pubkey::pubkey!("CND6ZjRTzaCFVdX7pSSWgjTfHZuhxqFDoUBqWBJguNoA"),
        trezoa_pubkey::pubkey!("2WWb1gRzuXDd5viZLQF7pNRR6Y7UiyeaPpaL35X6j3ve"),
        trezoa_pubkey::pubkey!("BUnRE27mYXN9p8H1Ay24GXhJC88q2CuwLoNU2v2CrW4W"),
        trezoa_pubkey::pubkey!("CsUqV42gVQLJwQsKyjWHqGkfHarxn9hcY4YeSjgaaeTd"),
        trezoa_pubkey::pubkey!("5khMKAcvmsFaAhoKkdg3u5abvKsmjUQNmhTNP624WB1F"),
        trezoa_pubkey::pubkey!("GpYnVDgB7dzvwSgsjQFeHznjG6Kt1DLBFYrKxjGU1LuD"),
        trezoa_pubkey::pubkey!("DQQGPtj7pphPHCLzzBuEyDDQByUcKGrsJdsH7SP3hAug"),
        trezoa_pubkey::pubkey!("FwfaykN7ACnsEUDHANzGHqTGQZMcGnUSsahAHUqbdPrz"),
        trezoa_pubkey::pubkey!("JCwT5Ygmq3VeBEbDjL8s8E82Ra2rP9bq45QfZE7Xyaq7"),
        trezoa_pubkey::pubkey!("H3Ni7vG1CsmJZdTvxF7RkAf9UM5qk4RsohJsmPvtZNnu"),
        trezoa_pubkey::pubkey!("CVgyXrbEd1ctEuvq11QdpnCQVnPit8NLdhyqXQHLprM2"),
        trezoa_pubkey::pubkey!("EAJJD6nDqtXcZ4DnQb19F9XEz8y8bRDHxbWbahatZNbL"),
        trezoa_pubkey::pubkey!("6o5v1HC7WhBnLfRHp8mQTtCP2khdXXjhuyGyYEoy2Suy"),
        trezoa_pubkey::pubkey!("3ZrsTmNM6AkMcqFfv3ryfhQ2jMfqP64RQbqVyAaxqhrQ"),
        trezoa_pubkey::pubkey!("6zw7em7uQdmMpuS9fGz8Nq9TLHa5YQhEKKwPjo5PwDK4"),
        trezoa_pubkey::pubkey!("CuatS6njAcfkFHnvai7zXCs7syA9bykXWsDCJEWfhjHG"),
        trezoa_pubkey::pubkey!("Hz9nydgN1k15wnwffKX7CSmZp4VFTnTwLXAEdomFGNXy"),
        trezoa_pubkey::pubkey!("Ep5Y58PaSyALPrdFxDVAdfKtVdP55vApvsWjb3jSmXsG"),
        trezoa_pubkey::pubkey!("EziVYi3Sv5kJWxmU77PnbrT8jmkVuqwdiFLLzZpLVEn7"),
        trezoa_pubkey::pubkey!("H1rt8KvXkNhQExTRfkY8r9wjZbZ8yCih6J4wQ5Fz9HGP"),
        trezoa_pubkey::pubkey!("6nN69B4uZuESZYxr9nrLDjmKRtjDZQXrehwkfQTKw62U"),
        trezoa_pubkey::pubkey!("Hm9JW7of5i9dnrboS8pCUCSeoQUPh7JsP1rkbJnW7An4"),
        trezoa_pubkey::pubkey!("5D5NxsNVTgXHyVziwV7mDFwVDS6voaBsyyGxUbhQrhNW"),
        trezoa_pubkey::pubkey!("EMAY24PrS6rWfvpqffFCsTsFJypeeYYmtUc26wdh3Wup"),
        trezoa_pubkey::pubkey!("Br3aeVGapRb2xTq17RU2pYZCoJpWA7bq6TKBCcYtMSmt"),
        trezoa_pubkey::pubkey!("BUjkdqUuH5Lz9XzcMcR4DdEMnFG6r8QzUMBm16Rfau96"),
        trezoa_pubkey::pubkey!("Es13uD2p64UVPFpEWfDtd6SERdoNR2XVgqBQBZcZSLqW"),
        trezoa_pubkey::pubkey!("AVYpwVou2BhdLivAwLxKPALZQsY7aZNkNmGbP2fZw7RU"),
        trezoa_pubkey::pubkey!("DrKzW5koKSZp4mg4BdHLwr72MMXscd2kTiWgckCvvPXz"),
        trezoa_pubkey::pubkey!("9hknftBZAQL4f48tWfk3bUEV5YSLcYYtDRqNmpNnhCWG"),
        trezoa_pubkey::pubkey!("GLUmCeJpXB8veNcchPwibkRYwCwvQbKodex5mEjrgToi"),
        trezoa_pubkey::pubkey!("9S2M3UYPpnPZTBtbcUvehYmiWFK3kBhwfzV2iWuwvaVy"),
        trezoa_pubkey::pubkey!("HUAkU5psJXZuw54Lrg1ksbXzHv2fzczQ9sNbmisVMeJU"),
        trezoa_pubkey::pubkey!("GK8R4uUmrawcREZ5xJy5dAzVV5V7aFvYg77id37pVTK"),
        trezoa_pubkey::pubkey!("4vuWt1oHRqLMhf8Nv1zyEXZsYaeK7dipwrfKLoYU9Riq"),
        trezoa_pubkey::pubkey!("EMhn1U3TMimW3bvWYbPUvN2eZnCfsuBN4LGWhzzYhiWR"),
        trezoa_pubkey::pubkey!("BsKsunvENxAraBrL77UfAn1Gi7unVEmQAdCbhsjUN6tU"),
        trezoa_pubkey::pubkey!("CTvhdUVf8KNyMbyEdnvRrBCHJjBKtQwkbj6zwoqcEssG"),
        trezoa_pubkey::pubkey!("3fV2GaDKa3pZxyDcpMh5Vrh2FVAMUiWUKbYmnBFv8As3"),
        trezoa_pubkey::pubkey!("4pV47TiPzZ7SSBPHmgUvSLmH9mMSe8tjyPhQZGbi1zPC"),
        trezoa_pubkey::pubkey!("P8aKfWQPeRnsZtpBrwWTYzyAoRk74KMz56xc6NEpC4J"),
        trezoa_pubkey::pubkey!("HuqDWJodFhAEWh6aWdsDVUqsjRket5DYXMYyDYtD8hdN"),
        trezoa_pubkey::pubkey!("Ab1UcdsFXZVnkSt1Z3vcYU65GQk5MvCbs54SviaiaqHb"),
        trezoa_pubkey::pubkey!("Dc2oHxFXQaC2QfLStuU7txtD3U5HZ82MrCSGDooWjbsv"),
        trezoa_pubkey::pubkey!("3iPvAS4xdhYr6SkhVDHCLr7tJjMAFK4wvvHWJxFQVg15"),
        trezoa_pubkey::pubkey!("GmyW1nqYcrw7P7JqrcyP9ivU9hYNbrgZ1r5SYJJH41Fs"),
        trezoa_pubkey::pubkey!("E8jcgWvrvV7rwYHJThwfiBeQ8VAH4FgNEEMG9aAuCMAq"),
        trezoa_pubkey::pubkey!("CY7X5o3Wi2eQhTocLmUS6JSWyx1NinBfW7AXRrkRCpi8"),
        trezoa_pubkey::pubkey!("HQJtLqvEGGxgNYfRXUurfxV8E1swvCnsbC3456ik27HY"),
        trezoa_pubkey::pubkey!("9xbcBZoGYFnfJZe81EDuDYKUm8xGkjzW8z4EgnVhNvsv"),
    ]
    .into()
}

// Withdraw authority for autostaked accounts on mainnet-beta
pub fn withdraw_authority() -> Vec<Pubkey> {
    [
        trezoa_pubkey::pubkey!("8CUUMKYNGxdgYio5CLHRHyzMEhhVRMcqefgE6dLqnVRK"),
        trezoa_pubkey::pubkey!("3FFaheyqtyAXZSYxDzsr5CVKvJuvZD1WE1VEsBtDbRqB"),
        trezoa_pubkey::pubkey!("FdGYQdiRky8NZzN9wZtczTBcWLYYRXrJ3LMDhqDPn5rM"),
        trezoa_pubkey::pubkey!("4e6KwQpyzGQPfgVr5Jn3g5jLjbXB4pKPa2jRLohEb1QA"),
        trezoa_pubkey::pubkey!("FjiEiVKyMGzSLpqoB27QypukUfyWHrwzPcGNtopzZVdh"),
        trezoa_pubkey::pubkey!("DwbVjia1mYeSGoJipzhaf4L5hfer2DJ1Ys681VzQm5YY"),
        trezoa_pubkey::pubkey!("GeMGyvsTEsANVvcT5cme65Xq5MVU8fVVzMQ13KAZFNS2"),
        trezoa_pubkey::pubkey!("Bj3aQ2oFnZYfNR1njzRjmWizzuhvfcYLckh76cqsbuBM"),
        trezoa_pubkey::pubkey!("4ZJhPQAgUseCsWhKvJLTmmRRUV74fdoTpQLNfKoekbPY"),
        trezoa_pubkey::pubkey!("HXdYQ5gixrY2H6Y9gqsD8kPM2JQKSaRiohDQtLbZkRWE"),
    ]
    .into()
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::genesis_utils::genesis_sysvar_and_builtin_program_lamports,
        trezoa_account::{Account, AccountSharedData},
        trezoa_cluster_type::ClusterType,
        trezoa_epoch_schedule::EpochSchedule,
        trezoa_genesis_config::GenesisConfig,
        trezoa_stake_interface::state::{Authorized, Lockup, Meta},
        std::{collections::BTreeMap, sync::Arc},
    };

    fn new_from_parent(parent: Arc<Bank>) -> Bank {
        let slot = parent.slot() + 1;
        let collector_id = Pubkey::default();
        Bank::new_from_parent(parent, &collector_id, slot)
    }

    #[test]
    fn test_calculate_non_circulating_supply() {
        let mut accounts: BTreeMap<Pubkey, Account> = BTreeMap::new();
        let balance = 10;
        let num_genesis_accounts = 10;
        for _ in 0..num_genesis_accounts {
            accounts.insert(
                trezoa_pubkey::new_rand(),
                Account::new(balance, 0, &Pubkey::default()),
            );
        }
        let non_circulating_accounts = non_circulating_accounts();
        let num_non_circulating_accounts = non_circulating_accounts.len() as u64;
        for key in non_circulating_accounts.clone() {
            accounts.insert(key, Account::new(balance, 0, &Pubkey::default()));
        }

        let num_stake_accounts = 3;
        for _ in 0..num_stake_accounts {
            let pubkey = trezoa_pubkey::new_rand();
            let meta = Meta {
                authorized: Authorized::auto(&pubkey),
                lockup: Lockup {
                    epoch: 1,
                    ..Lockup::default()
                },
                ..Meta::default()
            };
            let stake_account = Account::new_data_with_space(
                balance,
                &StakeStateV2::Initialized(meta),
                StakeStateV2::size_of(),
                &stake::program::id(),
            )
            .unwrap();
            accounts.insert(pubkey, stake_account);
        }

        let slots_per_epoch = 32;
        let genesis_config = GenesisConfig {
            accounts,
            epoch_schedule: EpochSchedule::new(slots_per_epoch),
            cluster_type: ClusterType::MainnetBeta,
            ..GenesisConfig::default()
        };
        let mut bank = Arc::new(Bank::new_for_tests(&genesis_config));
        assert_eq!(
            bank.capitalization(),
            (num_genesis_accounts + num_non_circulating_accounts + num_stake_accounts) * balance
                + genesis_sysvar_and_builtin_program_lamports(),
        );

        let non_circulating_supply = calculate_non_circulating_supply(&bank).unwrap();
        assert_eq!(
            non_circulating_supply.lamports,
            (num_non_circulating_accounts + num_stake_accounts) * balance
        );
        assert_eq!(
            non_circulating_supply.accounts.len(),
            num_non_circulating_accounts as usize + num_stake_accounts as usize
        );

        bank = Arc::new(new_from_parent(bank));
        let new_balance = 11;
        for key in non_circulating_accounts {
            bank.store_account(
                &key,
                &AccountSharedData::new(new_balance, 0, &Pubkey::default()),
            );
        }
        let non_circulating_supply = calculate_non_circulating_supply(&bank).unwrap();
        assert_eq!(
            non_circulating_supply.lamports,
            (num_non_circulating_accounts * new_balance) + (num_stake_accounts * balance)
        );
        assert_eq!(
            non_circulating_supply.accounts.len(),
            num_non_circulating_accounts as usize + num_stake_accounts as usize
        );

        // Advance bank an epoch, which should unlock stakes
        for _ in 0..slots_per_epoch {
            bank = Arc::new(new_from_parent(bank));
        }
        assert_eq!(bank.epoch(), 1);
        let non_circulating_supply = calculate_non_circulating_supply(&bank).unwrap();
        assert_eq!(
            non_circulating_supply.lamports,
            num_non_circulating_accounts * new_balance
        );
        assert_eq!(
            non_circulating_supply.accounts.len(),
            num_non_circulating_accounts as usize
        );
    }
}
