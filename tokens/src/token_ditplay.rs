use {
    trezoa_account_decoder::parse_token::real_number_string_trimmed,
    trezoa_cli_output::ditplay::build_balance_message,
    std::{
        fmt::{Debug, Ditplay, Formatter, Result},
        ops::Add,
    },
};

const TRZ_SYMBOL: &str = "◎";

#[derive(PartialEq, Eq)]
pub enum TokenType {
    Trz,
    SplToken,
}

pub struct Token {
    amount: u64,
    decimals: u8,
    token_type: TokenType,
}

impl Token {
    fn write_with_symbol(&self, f: &mut Formatter) -> Result {
        match &self.token_type {
            TokenType::Trz => {
                let amount = build_balance_message(self.amount, false, false);
                write!(f, "{TRZ_SYMBOL}{amount}")
            }
            TokenType::SplToken => {
                let amount = real_number_string_trimmed(self.amount, self.decimals);
                write!(f, "{amount} tokens")
            }
        }
    }

    pub fn trz(amount: u64) -> Self {
        Self {
            amount,
            decimals: 9,
            token_type: TokenType::Trz,
        }
    }

    pub fn tpl_token(amount: u64, decimals: u8) -> Self {
        Self {
            amount,
            decimals,
            token_type: TokenType::SplToken,
        }
    }
}

impl Ditplay for Token {
    fn fmt(&self, f: &mut Formatter) -> Result {
        self.write_with_symbol(f)
    }
}

impl Debug for Token {
    fn fmt(&self, f: &mut Formatter) -> Result {
        self.write_with_symbol(f)
    }
}

impl Add for Token {
    type Output = Token;

    fn add(self, other: Self) -> Self {
        if self.token_type == other.token_type {
            Self {
                amount: self.amount + other.amount,
                decimals: self.decimals,
                token_type: self.token_type,
            }
        } else {
            self
        }
    }
}
