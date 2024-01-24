use chia_bls::Signature;
use chia_protocol::{Coin, CoinSpend, SpendBundle};
use serde::{Deserialize, Serialize};

use crate::utils::{bytes_to_program, program_to_bytes, strip_prefix};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendBundleJson {
    pub coin_spends: Vec<CoinSpendJson>,
    pub aggregated_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinSpendJson {
    pub coin: CoinJson,
    pub puzzle_reveal: String,
    pub solution: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinJson {
    pub parent_coin_info: String,
    pub puzzle_hash: String,
    pub amount: u64,
}

// Maybe use `TryFrom`?
impl From<SpendBundleJson> for SpendBundle {
    fn from(value: SpendBundleJson) -> Self {
        let aggregated_signature = hex::decode(strip_prefix(&value.aggregated_signature))
            .expect("invalid aggregated signature");
        let aggregated_signature: [u8; 96] = aggregated_signature
            .try_into()
            .expect("invalid aggregated signature");

        Self {
            coin_spends: value.coin_spends.into_iter().map(From::from).collect(),
            aggregated_signature: Signature::from_bytes(&aggregated_signature)
                .expect("invalid aggregated signature"),
        }
    }
}

// Maybe use `TryFrom`?
impl From<CoinSpendJson> for CoinSpend {
    fn from(value: CoinSpendJson) -> Self {
        let puzzle_reveal =
            hex::decode(strip_prefix(&value.puzzle_reveal)).expect("invalid puzzle reveal");
        let solution = hex::decode(strip_prefix(&value.solution)).expect("invalid solution");

        Self {
            coin: value.coin.into(),
            puzzle_reveal: bytes_to_program(puzzle_reveal),
            solution: bytes_to_program(solution),
        }
    }
}

// Maybe use `TryFrom`?
impl From<CoinJson> for Coin {
    fn from(value: CoinJson) -> Self {
        let parent_coin_info =
            hex::decode(strip_prefix(&value.parent_coin_info)).expect("invalid parent coin info");
        let puzzle_hash =
            hex::decode(strip_prefix(&value.puzzle_hash)).expect("invalid puzzle hash");

        let parent_coin_info: [u8; 32] = parent_coin_info
            .try_into()
            .expect("invalid parent coin info");
        let puzzle_hash: [u8; 32] = puzzle_hash.try_into().expect("invalid puzzle hash");

        Self {
            parent_coin_info: parent_coin_info.into(),
            puzzle_hash: puzzle_hash.into(),
            amount: value.amount,
        }
    }
}

impl From<SpendBundle> for SpendBundleJson {
    fn from(value: SpendBundle) -> Self {
        Self {
            coin_spends: value.coin_spends.into_iter().map(From::from).collect(),
            aggregated_signature: hex::encode(value.aggregated_signature.to_bytes()),
        }
    }
}

impl From<CoinSpend> for CoinSpendJson {
    fn from(value: CoinSpend) -> Self {
        Self {
            coin: value.coin.into(),
            puzzle_reveal: hex::encode(program_to_bytes(value.puzzle_reveal)),
            solution: hex::encode(program_to_bytes(value.solution)),
        }
    }
}

impl From<Coin> for CoinJson {
    fn from(value: Coin) -> Self {
        Self {
            parent_coin_info: hex::encode(value.parent_coin_info),
            puzzle_hash: hex::encode(value.puzzle_hash),
            amount: value.amount,
        }
    }
}
