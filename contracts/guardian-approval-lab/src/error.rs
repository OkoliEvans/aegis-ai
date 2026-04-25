use cosmwasm_std::{OverflowError, StdError, Uint128};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    Overflow(#[from] OverflowError),

    #[error("unauthorized")]
    Unauthorized,

    #[error("invalid amount")]
    InvalidAmount,

    #[error("insufficient balance")]
    InsufficientBalance,

    #[error("demo balance already claimed")]
    AlreadyClaimed,

    #[error("allowance for {spender} is already zero")]
    AllowanceMissing { spender: String },

    #[error("cannot reduce allowance below zero: current={current}, delta={delta}")]
    AllowanceUnderflow { current: Uint128, delta: Uint128 },
}
