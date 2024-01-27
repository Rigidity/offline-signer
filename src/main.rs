use std::{fs, str::FromStr, sync::Arc};

use bip39::Mnemonic;
use chia_bls::{SecretKey, Signature};
use chia_protocol::{Coin, NodeType, SpendBundle};
use chia_wallet::standard::STANDARD_PUZZLE;
use chia_wallet_sdk::{
    connect_peer, create_tls_connector, load_ssl_cert, parse_address, select_coins,
    sign_spend_bundle, spend_standard_coins, CoinStore, Condition, CreateCoin, DerivationStore,
    MemoryCoinStore, SyncConfig,
};
use clap::Parser;
use cli::{Cli, Commands};
use clvmr::{serde::node_from_bytes, Allocator};
use colored::Colorize;
use config::Config;
use database::WalletDb;
use inquire::Confirm;
use keys::{ConfigKey, WalletKey};
use spend_bundle::SpendBundleJson;
use tokio::sync::mpsc;
use utils::{amount_as_mojos, program_name, strip_prefix, Paths};

mod cli;
mod config;
mod database;
mod keys;
mod spend_bundle;
mod utils;

#[tokio::main]
async fn main() {
    let paths = Paths::new();
    let program_name = program_name().unwrap_or("offline-signer".to_string());

    let cli = Cli::parse();

    let config_str_owned = fs::read_to_string(paths.config.as_path()).ok();
    let config_str = config_str_owned.as_ref();

    let config: Option<Config> =
        config_str.and_then(|config_str| serde_json::from_str(config_str).ok());

    if let Commands::Config {
        key: cli_key,
        node_uri,
        network_id,
        agg_sig_data,
    } = cli.command
    {
        if !cli_key.generate
            && cli_key.public_key.is_none()
            && cli_key.secret_key.is_none()
            && cli_key.mnemonic.is_none()
            && node_uri.is_none()
            && network_id.is_none()
            && agg_sig_data.is_none()
        {
            println!("Config at path `{}`", paths.config.to_str().unwrap());
            return;
        }

        let old_config = config.as_ref();

        let mut key = old_config.map(|config| config.key.clone());
        let generated = cli_key.generate;

        if let Some(old_key) = key.as_mut() {
            if let Some(new_key) = ConfigKey::from_cli(cli_key) {
                if !cli.yes
                    && !Confirm::new("Are you sure you want to replace the key?")
                        .prompt()
                        .unwrap()
                {
                    return;
                }

                if generated {
                    let ConfigKey::Mnemonic(mnemonic) = &new_key else {
                        unreachable!();
                    };

                    let mnemonic = Mnemonic::from_str(mnemonic).unwrap();
                    let secret_key = SecretKey::from_seed(&mnemonic.to_seed(""));
                    let public_key = secret_key.public_key();

                    println!(
                        "{}",
                        format!("Public key = {}", hex::encode(public_key.to_bytes()))
                            .bright_yellow()
                    );
                    println!(
                        "{}",
                        format!("Fingerprint = {}", public_key.get_fingerprint()).bright_magenta()
                    );
                }

                *old_key = new_key;
            }
        }

        let agg_sig_data = agg_sig_data
            .or_else(|| old_config.map(|config| config.agg_sig_data.clone()))
            .unwrap_or_else(|| {
                "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb".to_string()
            });

        let bytes = hex::decode(strip_prefix(&agg_sig_data)).expect("invalid agg_sig_data");
        let _: [u8; 32] = bytes.try_into().expect("invalid agg_sig_data");

        let config = Config {
            key: key.expect("missing key in config"),
            node_uri: node_uri.or_else(|| old_config.and_then(|config| config.node_uri.clone())),
            network_id: network_id
                .or_else(|| old_config.map(|config| config.network_id.clone()))
                .unwrap_or_else(|| "mainnet".to_string()),
            agg_sig_data,
        };

        let config_str = serde_json::to_string_pretty(&config).expect("could not serialize config");

        fs::write(paths.config.as_path(), config_str).unwrap_or_else(|_| {
            panic!(
                "could not write config file to {}",
                paths.config.to_str().unwrap()
            )
        });

        return println!("Config file initialized!");
    }

    config_str
        .unwrap_or_else(|| panic!("no config file found, try running `{} init`", &program_name));
    let config = config.expect("invalid config file");

    let key = WalletKey::from_config(config.key.clone());

    let fingerprint = match &key {
        WalletKey::PublicKey(pk) => pk.get_fingerprint(),
        WalletKey::SecretKey(sk) => sk.public_key().get_fingerprint(),
    };

    let db_path = paths.db_dir.join(format!("{fingerprint}.sqlite?mode=rwc"));
    let derivation_store_sync = Arc::new(
        WalletDb::new(db_path.to_str().unwrap(), key.clone())
            .await
            .unwrap(),
    );

    if let Commands::Sign {
        spend_bundle: spend_bundle_path,
        derivation_index,
    } = &cli.command
    {
        let spend_bundle_str =
            fs::read_to_string(spend_bundle_path).expect("could not read spend bundle file");
        let spend_bundle_json: SpendBundleJson =
            serde_json::from_str(&spend_bundle_str).expect("invalid spend bundle file");
        let mut spend_bundle = SpendBundle::from(spend_bundle_json);

        if let WalletKey::PublicKey(_) = &key {
            panic!("cannot sign with public key only, modify config to add secret key");
        }

        derivation_store_sync
            .derive_to_index(*derivation_index)
            .await;

        let agg_sig = hex::decode(config.agg_sig_data)
            .unwrap()
            .try_into()
            .unwrap();
        let mut a = Allocator::new();
        let signature = sign_spend_bundle(
            derivation_store_sync.as_ref(),
            &mut a,
            &spend_bundle,
            agg_sig,
        )
        .await
        .expect("could not sign spend bundle");

        spend_bundle.aggregated_signature = signature.clone();

        let spend_bundle_json = SpendBundleJson::from(spend_bundle);
        let output = serde_json::to_string_pretty(&spend_bundle_json).unwrap();

        fs::write(spend_bundle_path, output).unwrap();

        println!(
            "{}",
            format!(
                "Successfully updated signature to {}",
                hex::encode(signature.to_bytes())
            )
            .bright_green()
        );
    }

    let node_uri = config
        .node_uri
        .as_ref()
        .expect("`node_uri` is not set in config, cannot connect to peer");

    let cert = load_ssl_cert(
        paths.ssl_dir.join("wallet.crt").to_str().unwrap(),
        paths.ssl_dir.join("wallet.key").to_str().unwrap(),
    );
    let tls = create_tls_connector(&cert);
    let peer = connect_peer(node_uri, tls)
        .await
        .expect("could not connect to full node");

    peer.send_handshake(config.network_id, NodeType::Wallet)
        .await
        .unwrap();

    if let Commands::Push { spend_bundle } = cli.command {
        let spend_bundle_str =
            fs::read_to_string(spend_bundle).expect("could not read spend bundle file");
        let spend_bundle_json: SpendBundleJson =
            serde_json::from_str(&spend_bundle_str).expect("invalid spend bundle file");
        let spend_bundle = SpendBundle::from(spend_bundle_json);

        let response = peer
            .send_transaction(spend_bundle)
            .await
            .expect("could not send transaction");

        if let Some(error) = response.error {
            eprintln!(
                "{}",
                format!(
                    "Transaction {} failed with status {}: {}",
                    response.txid, response.status, error
                )
                .bright_red()
            );
        } else {
            println!(
                "{}",
                format!(
                    "Transaction {} pushed to mempool with status {}",
                    response.txid, response.status
                )
                .bright_green()
            );
        }
    } else if let Commands::Send {
        address,
        amount: cli_amount,
        fee: cli_fee,
    } = cli.command
    {
        let puzzle_hash = parse_address(&address);
        let send_amount = amount_as_mojos(cli_amount, cli.mojos);
        let fee_amount = amount_as_mojos(cli_fee, cli.mojos);

        let coin_store_sync = Arc::new(MemoryCoinStore::new());

        let derivation_store = derivation_store_sync.clone();
        let coin_store = coin_store_sync.clone();

        let (sender, mut receiver) = mpsc::channel(32);

        tokio::spawn(async move {
            let Some(()) = receiver.recv().await else {
                return;
            };

            let derivation_index = derivation_store.derivations().await;

            eprintln!(
                "{}",
                format!("Synced to derivation index {}", derivation_index).bright_green()
            );

            let total_amount = send_amount as u128 + fee_amount as u128;
            let mut coins = Vec::new();

            for coin in coin_store.unspent_coins().await {
                if derivation_store
                    .index_of_puzzle_hash((&coin.puzzle_hash).into())
                    .await
                    .is_some()
                {
                    coins.push(coin);
                }
            }

            let selected_coins: Vec<Coin> = select_coins(coins, total_amount)
                .unwrap()
                .into_iter()
                .collect();
            let selected_amount = selected_coins
                .iter()
                .fold(0u128, |acc, coin| acc + coin.amount as u128);
            let change_amount = (selected_amount - total_amount) as u64;

            let mut conditions = vec![
                Condition::CreateCoin(CreateCoin::Normal {
                    puzzle_hash: puzzle_hash.into(),
                    amount: send_amount,
                }),
                Condition::ReserveFee { amount: fee_amount },
            ];

            if change_amount > 0 {
                conditions.push(Condition::CreateCoin(CreateCoin::Normal {
                    puzzle_hash: selected_coins[0].puzzle_hash,
                    amount: change_amount,
                }));
            }

            let mut a = Allocator::new();
            let standard_puzzle_ptr = node_from_bytes(&mut a, &STANDARD_PUZZLE).unwrap();
            let coin_spends = spend_standard_coins(
                &mut a,
                standard_puzzle_ptr,
                derivation_store.as_ref(),
                selected_coins,
                &conditions,
            )
            .await;

            let spend_bundle = SpendBundle::new(coin_spends, Signature::default());
            let spend_bundle_json = SpendBundleJson::from(spend_bundle);

            let output = serde_json::to_string_pretty(&spend_bundle_json).unwrap();
            println!("{}", output);

            std::process::exit(0);
        });

        eprintln!(
            "{}",
            format!("Fetching coins with fingerprint {fingerprint}").bright_yellow()
        );

        chia_wallet_sdk::incremental_sync(
            peer,
            derivation_store_sync,
            coin_store_sync,
            SyncConfig {
                minimum_unused_derivations: 100,
            },
            sender,
        )
        .await
        .unwrap();
    }
}
