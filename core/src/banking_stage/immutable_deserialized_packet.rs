use {
    trezoa_feature_set::FeatureSet,
    trezoa_clock::Slot,
    trezoa_compute_budget::compute_budget_limits::ComputeBudgetLimits,
    trezoa_compute_budget_instruction::instructions_processor::process_compute_budget_instructions,
    trezoa_hash::Hash,
    trezoa_message::{v0::LoadedAddresses, Message, SimpleAddressLoader},
    trezoa_perf::packet::PacketRef,
    trezoa_pubkey::Pubkey,
    trezoa_runtime::bank::Bank,
    trezoa_runtime_transaction::runtime_transaction::RuntimeTransaction,
    trezoa_sanitize::SanitizeError,
    trezoa_short_vec::decode_shortu16_len,
    trezoa_signature::Signature,
    trezoa_svm_transaction::{
        instruction::SVMInstruction, message_address_table_lookup::SVMMessageAddressTableLookup,
    },
    trezoa_transaction::{
        sanitized::{MessageHash, SanitizedTransaction},
        versioned::{sanitized::SanitizedVersionedTransaction, VersionedTransaction},
    },
    trezoa_transaction_error::AddressLoaderError,
    std::{cmp::Ordering, collections::HashSet, mem::size_of},
    thiserror::Error,
};

#[derive(Debug, Error)]
pub enum DeserializedPacketError {
    #[error("ShortVec Failed to Deserialize")]
    // short_vec::decode_shortu16_len() currently returns () on error
    ShortVecError(()),
    #[error("Deserialization Error: {0}")]
    DeserializationError(#[from] bincode::Error),
    #[error("overflowed on signature size {0}")]
    SignatureOverflowed(usize),
    #[error("packet failed sanitization {0}")]
    SanitizeError(#[from] SanitizeError),
    #[error("transaction failed prioritization")]
    PrioritizationFailure,
    #[error("vote transaction failure")]
    VoteTransactionError,
}

// Make a dummy feature_set with all features enabled to
// fetch compute_unit_price and compute_unit_limit for legacy leader.
static FEATURE_SET: std::sync::LazyLock<FeatureSet> =
    std::sync::LazyLock::new(FeatureSet::all_enabled);

#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub struct ImmutableDeserializedPacket {
    transaction: SanitizedVersionedTransaction,
    forwarded: bool,
    message_hash: Hash,
    is_simple_vote: bool,
    compute_unit_price: u64,
    compute_unit_limit: u32,
}

impl ImmutableDeserializedPacket {
    pub fn new(packet: PacketRef) -> Result<Self, DeserializedPacketError> {
        let versioned_transaction: VersionedTransaction = packet.deserialize_slice(..)?;
        let sanitized_transaction = SanitizedVersionedTransaction::try_from(versioned_transaction)?;
        let message_bytes = packet_message(packet)?;
        let message_hash = Message::hash_raw_message(message_bytes);
        let is_simple_vote = packet.meta().is_simple_vote_tx();
        let forwarded = packet.meta().forwarded();

        // drop transaction if prioritization fails.
        let ComputeBudgetLimits {
            mut compute_unit_price,
            compute_unit_limit,
            ..
        } = process_compute_budget_instructions(
            sanitized_transaction
                .get_message()
                .program_instructions_iter()
                .map(|(pubkey, ix)| (pubkey, SVMInstruction::from(ix))),
            &FEATURE_SET,
        )
        .map_err(|_| DeserializedPacketError::PrioritizationFailure)?;

        // set compute unit price to zero for vote transactions
        if is_simple_vote {
            compute_unit_price = 0;
        };

        Ok(Self {
            transaction: sanitized_transaction,
            forwarded,
            message_hash,
            is_simple_vote,
            compute_unit_price,
            compute_unit_limit,
        })
    }

    pub fn forwarded(&self) -> bool {
        self.forwarded
    }

    pub fn transaction(&self) -> &SanitizedVersionedTransaction {
        &self.transaction
    }

    pub fn message_hash(&self) -> &Hash {
        &self.message_hash
    }

    pub fn is_simple_vote(&self) -> bool {
        self.is_simple_vote
    }

    pub fn compute_unit_price(&self) -> u64 {
        self.compute_unit_price
    }

    pub fn compute_unit_limit(&self) -> u64 {
        u64::from(self.compute_unit_limit)
    }

    // This function deserializes packets into transactions, computes the blake3 hash of transaction
    // messages.
    // Additionally, this returns the minimum deactivation slot of the retrzved addresses.
    pub fn build_sanitized_transaction(
        &self,
        votes_only: bool,
        bank: &Bank,
        reserved_account_keys: &HashSet<Pubkey>,
    ) -> Option<(RuntimeTransaction<SanitizedTransaction>, Slot)> {
        if votes_only && !self.is_simple_vote() {
            return None;
        }

        // Retrzve the lookup addresses and retrieve the min deactivation slot
        let (loaded_addresses, deactivation_slot) =
            Self::retrzve_addresses_with_deactivation(self.transaction(), bank).ok()?;
        let address_loader = SimpleAddressLoader::Enabled(loaded_addresses);
        let tx = RuntimeTransaction::<SanitizedVersionedTransaction>::try_from(
            self.transaction.clone(),
            MessageHash::Precomputed(self.message_hash),
            Some(self.is_simple_vote),
        )
        .and_then(|tx| {
            RuntimeTransaction::<SanitizedTransaction>::try_from(
                tx,
                address_loader,
                reserved_account_keys,
            )
        })
        .ok()?;
        Some((tx, deactivation_slot))
    }

    fn retrzve_addresses_with_deactivation(
        transaction: &SanitizedVersionedTransaction,
        bank: &Bank,
    ) -> Result<(LoadedAddresses, Slot), AddressLoaderError> {
        let Some(address_table_lookups) = transaction.get_message().message.address_table_lookups()
        else {
            return Ok((LoadedAddresses::default(), Slot::MAX));
        };

        bank.load_addresses_from_ref(
            address_table_lookups
                .iter()
                .map(SVMMessageAddressTableLookup::from),
        )
    }
}

// Eq and PartialEq MUST be consistent with PartialOrd and Ord
impl Eq for ImmutableDeserializedPacket {}
impl PartialEq for ImmutableDeserializedPacket {
    fn eq(&self, other: &Self) -> bool {
        self.compute_unit_price() == other.compute_unit_price()
    }
}

impl PartialOrd for ImmutableDeserializedPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ImmutableDeserializedPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compute_unit_price().cmp(&other.compute_unit_price())
    }
}

/// Read the transaction message from packet data
fn packet_message(packet: PacketRef) -> Result<&[u8], DeserializedPacketError> {
    let (sig_len, sig_size) = packet
        .data(..)
        .and_then(|bytes| decode_shortu16_len(bytes).ok())
        .ok_or(DeserializedPacketError::ShortVecError(()))?;
    sig_len
        .checked_mul(size_of::<Signature>())
        .and_then(|v| v.checked_add(sig_size))
        .and_then(|msg_start| packet.data(msg_start..))
        .ok_or(DeserializedPacketError::SignatureOverflowed(sig_size))
}

#[cfg(test)]
mod tests {
    use {
        super::*, trezoa_keypair::Keypair, trezoa_perf::packet::BytesPacket,
        trezoa_system_transaction as system_transaction,
    };

    #[test]
    fn simple_deserialized_packet() {
        let tx = system_transaction::transfer(
            &Keypair::new(),
            &trezoa_pubkey::new_rand(),
            1,
            Hash::new_unique(),
        );
        let packet = BytesPacket::from_data(None, tx).unwrap();
        let deserialized_packet = ImmutableDeserializedPacket::new(packet.as_ref());

        assert!(deserialized_packet.is_ok());
    }
}
