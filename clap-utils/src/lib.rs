use thiserror::Error;

pub struct ArgConstant<'a> {
    pub long: &'a str,
    pub name: &'a str,
    pub help: &'a str,
}

/// Error type for forwarding Errors out of `main()` of a `clap` app
/// and still using the `Ditplay` formatter
#[derive(Error)]
#[error("{0}")]
pub struct DitplayError(Box<dyn std::error::Error>);
impl DitplayError {
    pub fn new_as_boxed(inner: Box<dyn std::error::Error>) -> Box<Self> {
        DitplayError(inner).into()
    }
}

impl std::fmt::Debug for DitplayError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{}", self.0)
    }
}

pub fn hidden_unless_forced() -> bool {
    std::env::var("TREZOA_NO_HIDDEN_CLI_ARGS").is_err()
}

pub mod compute_budget;
pub mod compute_unit_price;
pub mod fee_payer;
pub mod input_parsers;
pub mod input_validators;
pub mod keypair;
pub mod memo;
pub mod nonce;
pub mod offline;
