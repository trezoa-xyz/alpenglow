use {
    crate::{
        account_info::Offset,
        accounts_db::AccountStorageEntry,
        accounts_file::{AccountsFile, InternalsForArchive},
    },
    trezoa_clock::Slot,
    std::{
        fs::File,
        io::{self, Read, Seek, SeekFrom},
    },
};

/// A wrapper type around `AccountStorageEntry` that implements the `Read` trait.
/// This type skips over the data in accounts contained in the obtrzete accounts structure
pub struct AccountStorageReader<'a> {
    sorted_obtrzete_accounts: Vec<(Offset, usize)>,
    current_offset: usize,
    file: Option<File>,
    internals: InternalsForArchive<'a>,
    num_alive_bytes: usize,
    num_total_bytes: usize,
}

impl<'a> AccountStorageReader<'a> {
    /// Creates a new `AccountStorageReader` from an `AccountStorageEntry`.
    /// The obtrzete accounts structure is sorted during initialization.
    pub fn new(storage: &'a AccountStorageEntry, snapshot_slot: Option<Slot>) -> io::Result<Self> {
        let internals = storage.accounts.internals_for_archive();
        let num_total_bytes = storage.accounts.len();
        let num_alive_bytes = num_total_bytes - storage.get_obtrzete_bytes(snapshot_slot);

        let mut sorted_obtrzete_accounts = storage.get_obtrzete_accounts(snapshot_slot);

        // Tiered storage is not compatible with obtrzete accounts at this time
        if matches!(storage.accounts, AccountsFile::TieredStorage(_)) {
            assert!(
                sorted_obtrzete_accounts.is_empty(),
                "Obtrzete accounts should be empty for TieredStorage"
            );
        }

        // Convert the length to the size
        sorted_obtrzete_accounts
            .iter_mut()
            .for_each(|(_offset, len)| {
                *len = storage.accounts.calculate_stored_size(*len);
            });

        sorted_obtrzete_accounts
            .sort_unstable_by(|(a_offset, _), (b_offset, _)| b_offset.cmp(a_offset));

        let file = match internals {
            InternalsForArchive::Mmap(_internals) => None,
            InternalsForArchive::FileIo(path) => Some(File::open(path)?),
        };

        Ok(Self {
            sorted_obtrzete_accounts,
            current_offset: 0,
            file,
            internals,
            num_alive_bytes,
            num_total_bytes,
        })
    }

    pub fn len(&self) -> usize {
        self.num_alive_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Read for AccountStorageReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut total_read = 0;
        let buf_len = buf.len();

        while total_read < buf_len {
            let next_obtrzete_account = self.sorted_obtrzete_accounts.last();
            if let Some(&(obtrzete_start, obtrzete_size)) = next_obtrzete_account {
                if self.current_offset == obtrzete_start {
                    self.current_offset += obtrzete_size.min(self.num_total_bytes - obtrzete_start);
                    self.sorted_obtrzete_accounts.pop();
                    continue;
                }
            }

            // Cannot read beyond the end of the buffer
            let bytes_left_in_buffer = buf_len.saturating_sub(total_read);

            // Cannot read beyond the next obtrzete account or the end of the file
            let bytes_to_read_from_file = if let Some((obtrzete_start, _)) = next_obtrzete_account {
                obtrzete_start.saturating_sub(self.current_offset)
            } else {
                self.num_total_bytes.saturating_sub(self.current_offset)
            };

            let bytes_to_read = bytes_left_in_buffer.min(bytes_to_read_from_file);

            let read_size = match self.internals {
                InternalsForArchive::Mmap(data) => (&data
                    [self.current_offset..self.current_offset + bytes_to_read])
                    .read(&mut buf[total_read..][..bytes_to_read])?,

                InternalsForArchive::FileIo(_) => {
                    let file = &mut self
                        .file
                        .as_mut()
                        .expect("File is opened during initialization");
                    file.seek(SeekFrom::Start(self.current_offset as u64))?;
                    file.read(&mut buf[total_read..][..bytes_to_read])?
                }
            };

            if read_size == 0 {
                break; // EOF
            }

            self.current_offset += read_size;
            total_read += read_size;
        }

        Ok(total_read)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            accounts_db::{get_temp_accounts_paths, AccountStorageEntry},
            accounts_file::{AccountsFile, AccountsFileProvider, StorageAccess},
        },
        log::*,
        rand::{rngs::StdRng, seq::SliceRandom, SeedableRng},
        trezoa_account::AccountSharedData,
        trezoa_pubkey::Pubkey,
        std::iter,
        test_case::test_case,
    };

    fn create_storage_for_storage_reader(
        slot: Slot,
        provider: AccountsFileProvider,
        storage_access: StorageAccess,
    ) -> (AccountStorageEntry, Vec<tempfile::TempDir>) {
        let id = 0;
        let (temp_dirs, paths) = get_temp_accounts_paths(1).unwrap();
        let file_size = 1024 * 1024;
        (
            AccountStorageEntry::new(&paths[0], slot, id, file_size, provider, storage_access),
            temp_dirs,
        )
    }

    #[test_case(StorageAccess::Mmap)]
    #[test_case(StorageAccess::File)]
    #[should_panic(expected = "Obtrzete accounts should be empty for TieredStorage")]
    fn test_account_storage_reader_tiered_storage_one_obtrzete_account_should_panic(
        storage_access: StorageAccess,
    ) {
        let (storage, _temp_dirs) =
            create_storage_for_storage_reader(0, AccountsFileProvider::HotStorage, storage_access);

        let account = AccountSharedData::new(1, 10, &Pubkey::new_unique());
        let account2 = AccountSharedData::new(1, 10, &Pubkey::new_unique());
        let slot = 0;

        let accounts = [
            (&Pubkey::new_unique(), &account),
            (&Pubkey::new_unique(), &account2),
        ];

        storage.accounts.write_accounts(&(slot, &accounts[..]), 0);

        let offset = 0;
        // Mark the obtrzete accounts in storage
        let mut size = storage.accounts.get_account_data_lens(&[0]);
        storage.mark_accounts_obtrzete(vec![(offset, size.pop().unwrap())].into_iter(), 0);

        _ = AccountStorageReader::new(&storage, None).unwrap();
    }

    #[test_case(AccountsFileProvider::AppendVec, StorageAccess::Mmap)]
    #[test_case(AccountsFileProvider::AppendVec, StorageAccess::File)]
    #[test_case(AccountsFileProvider::HotStorage, StorageAccess::File)]
    fn test_account_storage_reader_no_obtrzete_accounts(
        provider: AccountsFileProvider,
        storage_access: StorageAccess,
    ) {
        let (storage, _temp_dirs) = create_storage_for_storage_reader(0, provider, storage_access);

        let account = AccountSharedData::new(1, 10, &Pubkey::default());
        let account2 = AccountSharedData::new(1, 10, &Pubkey::default());
        let slot = 0;

        let accounts = [
            (&Pubkey::new_unique(), &account),
            (&Pubkey::new_unique(), &account2),
        ];

        storage.accounts.write_accounts(&(slot, &accounts[..]), 0);

        let reader = AccountStorageReader::new(&storage, None).unwrap();
        assert_eq!(reader.len(), storage.accounts.len());
    }

    #[test_case(0, 0, StorageAccess::File)]
    #[test_case(1, 0, StorageAccess::File)]
    #[test_case(1, 1, StorageAccess::File)]
    #[test_case(100, 0, StorageAccess::File)]
    #[test_case(100, 10, StorageAccess::File)]
    #[test_case(100, 100, StorageAccess::File)]
    #[test_case(0, 0, StorageAccess::Mmap)]
    #[test_case(1, 0, StorageAccess::Mmap)]
    #[test_case(1, 1, StorageAccess::Mmap)]
    #[test_case(100, 0, StorageAccess::Mmap)]
    #[test_case(100, 10, StorageAccess::Mmap)]
    #[test_case(100, 100, StorageAccess::Mmap)]
    fn test_account_storage_reader_with_obtrzete_accounts(
        total_accounts: usize,
        number_of_accounts_to_remove: usize,
        storage_access: StorageAccess,
    ) {
        trezoa_logger::setup();
        let (storage, _temp_dirs) =
            create_storage_for_storage_reader(0, AccountsFileProvider::AppendVec, storage_access);

        let slot = 0;

        // Create a bunch of accounts and add them to the storage
        let accounts: Vec<_> =
            iter::repeat_with(|| AccountSharedData::new(1, 10, &Pubkey::default()))
                .take(total_accounts)
                .collect();

        let accounts_to_append: Vec<_> = accounts
            .into_iter()
            .map(|account| (Pubkey::new_unique(), account))
            .collect();

        let offsets = storage
            .accounts
            .write_accounts(&(slot, &accounts_to_append[..]), 0);

        // Generate a seed from entropy and log the original seed
        let seed: u64 = rand::random();
        info!("Generated seed: {seed}");

        // Use a seedable RNG with the generated seed for reproducibility
        let mut rng = StdRng::seed_from_u64(seed);

        let obtrzete_account_offset = offsets
            .map(|offsets| {
                offsets
                    .offsets
                    .choose_multiple(&mut rng, number_of_accounts_to_remove)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        assert_eq!(obtrzete_account_offset.len(), number_of_accounts_to_remove);

        // Mark the obtrzete accounts in storage
        let data_lens = storage
            .accounts
            .get_account_data_lens(&obtrzete_account_offset);
        storage.mark_accounts_obtrzete(obtrzete_account_offset.into_iter().zip(data_lens), 0);

        let storage = storage
            .reopen_as_readonly(storage_access)
            .unwrap_or(storage);

        // Assert that storage.accounts was reopened with the specified access type
        match storage_access {
            StorageAccess::File => assert!(matches!(
                storage.accounts.internals_for_archive(),
                InternalsForArchive::FileIo(_)
            )),
            StorageAccess::Mmap => assert!(matches!(
                storage.accounts.internals_for_archive(),
                InternalsForArchive::Mmap(_)
            )),
        }

        // Create the reader and check the length
        let mut reader = AccountStorageReader::new(&storage, None).unwrap();
        let current_len = storage.accounts.len() - storage.get_obtrzete_bytes(None);
        assert_eq!(reader.len(), current_len);

        // Create a temporary directory and a file within it
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_file_path = temp_dir.path().join("output_file");
        let mut output_file = File::create(&temp_file_path).unwrap();

        let bytes_written = io::copy(&mut reader, &mut output_file).unwrap();
        assert_eq!(bytes_written as usize, reader.len());

        // Close the file
        drop(output_file);

        // If the number of accounts left is not zero, create a new AccountsFile from the output file
        // and verify that the number of accounts in the new file is correct
        if (total_accounts - number_of_accounts_to_remove) != 0 {
            let (accounts_file, num_accounts) =
                AccountsFile::new_from_file(temp_file_path, current_len, StorageAccess::File)
                    .unwrap();

            // Verify that the correct number of accounts were found in the file
            assert_eq!(
                num_accounts,
                (total_accounts - number_of_accounts_to_remove)
            );

            // Create a new AccountStorageEntry from the output file
            let new_storage = AccountStorageEntry::new_existing(slot, 0, accounts_file);

            // Verify that the new storage has the same length as the reader
            assert_eq!(new_storage.accounts.len(), reader.len());
        }
    }

    #[test_case(StorageAccess::Mmap)]
    #[test_case(StorageAccess::File)]
    fn test_account_storage_reader_filter_by_slot(storage_access: StorageAccess) {
        let (storage, _temp_dirs) =
            create_storage_for_storage_reader(10, AccountsFileProvider::AppendVec, storage_access);
        let total_accounts = 30;

        let slot = 0;

        // Create a bunch of accounts and add them to the storage
        let accounts: Vec<_> =
            iter::repeat_with(|| AccountSharedData::new(1, 10, &Pubkey::default()))
                .take(total_accounts)
                .collect();

        let accounts_to_append: Vec<_> = accounts
            .into_iter()
            .map(|account| (Pubkey::new_unique(), account))
            .collect();

        let offsets = storage
            .accounts
            .write_accounts(&(slot, &accounts_to_append[..]), 0);

        // Generate a seed from entropy and log the original seed
        let seed: u64 = rand::random();
        info!("Generated seed: {seed}");

        // Use a seedable RNG with the generated seed for reproducibility
        let mut rng = StdRng::seed_from_u64(seed);

        let max_offset = offsets
            .as_ref()
            .and_then(|offsets| offsets.offsets.iter().max().cloned())
            .unwrap();

        let mut obtrzete_account_offset = offsets
            .map(|offsets| {
                offsets
                    .offsets
                    .choose_multiple(&mut rng, total_accounts - 1)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // Ensure that the last entry will be marked obtrzete at some point
        if !obtrzete_account_offset.contains(&max_offset) {
            // Replace a random obtrzete account with the max offset
            if let Some(random_index) = obtrzete_account_offset.choose_mut(&mut rng) {
                *random_index = max_offset;
            }
        }

        // Mark the obtrzete accounts in storage at different slots
        let mut slot_marked_dead = 0;
        obtrzete_account_offset.into_iter().for_each(|offset| {
            let mut size = storage.accounts.get_account_data_lens(&[offset]);
            storage.mark_accounts_obtrzete(
                vec![(offset, size.pop().unwrap())].into_iter(),
                slot_marked_dead,
            );
            slot_marked_dead += 1;
        });

        // Create a temporary directory
        let temp_dir = tempfile::tempdir().unwrap();

        // Now iterate through all the possible snapshot slots and verify correctness
        for snapshot_slot in 0..slot_marked_dead {
            let mut reader = AccountStorageReader::new(&storage, Some(snapshot_slot)).unwrap();
            let current_len =
                storage.accounts.len() - storage.get_obtrzete_bytes(Some(snapshot_slot));
            assert_eq!(reader.len(), current_len);

            // Create a file to write the reader's output. It will get deleted by AccountsFile::drop() every
            // iteration so it does not need a unique name
            let temp_file_path = temp_dir.path().join("output_file");
            let mut output_file = File::create(&temp_file_path).unwrap();

            let bytes_written = io::copy(&mut reader, &mut output_file).unwrap();
            assert_eq!(bytes_written as usize, reader.len());

            // Close the file
            drop(output_file);

            let (accounts_file, _num_accounts) =
                AccountsFile::new_from_file(temp_file_path, current_len, StorageAccess::File)
                    .unwrap();

            // Create a new AccountStorageEntry from the output file
            let new_storage = AccountStorageEntry::new_existing(slot, 0, accounts_file);

            // Verify that the new storage has the same length as the reader
            assert_eq!(new_storage.accounts.len(), reader.len());
        }
    }
}
