use std::str::FromStr;

use bip39::Mnemonic;
use chia_bls::{derive_keys::master_to_wallet_unhardened_intermediate, PublicKey, SecretKey};
use clap::Args;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::utils::strip_prefix;

#[derive(Args)]
#[group(multiple = false)]
pub struct CliKey {
    /// Generates a new mnemonic phrase.
    #[arg(long)]
    pub generate: bool,

    /// The mnemonic phrase used by your wallet.
    #[arg(long)]
    pub mnemonic: Option<String>,

    /// The root secret key used by your wallet.
    #[arg(long)]
    pub secret_key: Option<String>,

    /// The root public key used by your wallet.
    #[arg(long)]
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigKey {
    Mnemonic(String),
    SecretKey(String),
    PublicKey(String),
}

#[derive(Debug, Clone)]
pub enum WalletKey {
    SecretKey(SecretKey),
    PublicKey(PublicKey),
}

impl ConfigKey {
    pub fn from_cli(value: CliKey) -> Option<Self> {
        if let Some(sk) = value.secret_key {
            let sk = strip_prefix(&sk);
            let bytes = hex::decode(sk).expect("invalid secret key");
            assert_eq!(bytes.len(), 32, "invalid secret key");
            Some(ConfigKey::SecretKey(sk.to_string()))
        } else if let Some(pk) = value.public_key {
            let pk = strip_prefix(&pk);
            let bytes = hex::decode(pk).expect("invalid public key");
            assert_eq!(bytes.len(), 48, "invalid public key");
            Some(ConfigKey::PublicKey(pk.to_string()))
        } else if let Some(mnemonic) = value.mnemonic {
            let mnemonic = Mnemonic::from_str(&mnemonic).expect("invalid mnemonic");
            Some(ConfigKey::Mnemonic(mnemonic.to_string()))
        } else if value.generate {
            let mut entropy = [0u8; 32];
            OsRng.fill_bytes(&mut entropy);
            let mnemonic = Mnemonic::from_entropy(&entropy).expect("could not generate mnemonic");
            Some(ConfigKey::Mnemonic(mnemonic.to_string()))
        } else {
            None
        }
    }
}

impl WalletKey {
    pub fn from_config(value: ConfigKey) -> Self {
        match value {
            ConfigKey::PublicKey(pk) => {
                let pk = strip_prefix(&pk);
                let bytes = hex::decode(pk).expect("invalid public key");
                let bytes: [u8; 48] = bytes.try_into().expect("invalid public key");
                let root_pk = PublicKey::from_bytes(&bytes).expect("invalid public key");
                let intermediate_pk = master_to_wallet_unhardened_intermediate(&root_pk);
                WalletKey::PublicKey(intermediate_pk)
            }
            ConfigKey::SecretKey(sk) => {
                let sk = strip_prefix(&sk);
                let bytes = hex::decode(sk).expect("invalid secret key");
                let bytes: [u8; 32] = bytes.try_into().expect("invalid secret key");
                let root_sk = SecretKey::from_bytes(&bytes).expect("invalid secret key");
                let intermediate_sk = master_to_wallet_unhardened_intermediate(&root_sk);
                WalletKey::SecretKey(intermediate_sk)
            }
            ConfigKey::Mnemonic(mnemonic) => {
                let mnemonic = Mnemonic::from_str(&mnemonic).expect("invalid mnemonic");
                let seed = mnemonic.to_seed("");
                let root_sk = SecretKey::from_seed(&seed);
                let intermediate_sk = master_to_wallet_unhardened_intermediate(&root_sk);
                WalletKey::SecretKey(intermediate_sk)
            }
        }
    }
}
