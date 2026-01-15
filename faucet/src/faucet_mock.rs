use {
    trezoa_hash::Hash,
    trezoa_keypair::Keypair,
    trezoa_pubkey::Pubkey,
    trezoa_system_transaction::transfer,
    trezoa_transaction::Transaction,
    std::{io::Error, net::SocketAddr},
};

pub fn request_airdrop_transaction(
    _faucet_addr: &SocketAddr,
    _id: &Pubkey,
    lamports: u64,
    _blockhash: Hash,
) -> Result<Transaction, Error> {
    if lamports == 0 {
        Err(Error::other("Airdrop failed"))
    } else {
        let key = Keypair::new();
        let to = trezoa_pubkey::new_rand();
        let blockhash = Hash::default();
        let tx = transfer(&key, &to, lamports, blockhash);
        Ok(tx)
    }
}
