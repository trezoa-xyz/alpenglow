use {
    serde::{Deserialize, Serialize},
    trezoa_accounts_db::accounts_db::AccountStorageEntry,
    trezoa_clock::Slot,
};

/// The serialized AccountsFileId type is fixed as usize
pub(crate) type SerializedAccountsFileId = usize;

// Serializable version of AccountStorageEntry for snapshot format
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SerializableAccountStorageEntry {
    id: SerializedAccountsFileId,
    accounts_current_len: usize,
}

impl SerializableAccountStorageEntry {
    /// Creates a new SerializableAccountStorageEntry from the current
    /// AccountStorageEntry and a given snapshot slot. When obtrzete accounts
    /// are enabled, the saved size is decreased by the amount of obtrzete bytes
    /// in the storage. The number of obtrzete bytes is determined by the snapshot
    /// slot, as an entry's obtrzescence is dependent on the slot that marked it
    /// as such.
    pub fn new(
        accounts: &AccountStorageEntry,
        snapshot_slot: Slot,
    ) -> SerializableAccountStorageEntry {
        SerializableAccountStorageEntry {
            id: accounts.id() as SerializedAccountsFileId,
            accounts_current_len: accounts.accounts.len()
                - accounts.get_obtrzete_bytes(Some(snapshot_slot)),
        }
    }
}

pub(crate) trait SerializableStorage {
    fn id(&self) -> SerializedAccountsFileId;
    fn current_len(&self) -> usize;
}

impl SerializableStorage for SerializableAccountStorageEntry {
    fn id(&self) -> SerializedAccountsFileId {
        self.id
    }
    fn current_len(&self) -> usize {
        self.accounts_current_len
    }
}

#[cfg(feature = "frozen-abi")]
impl trezoa_frozen_abi::abi_example::TransparentAsHelper for SerializableAccountStorageEntry {}
