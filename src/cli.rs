use clap::{Parser, Subcommand};

use crate::keys::CliKey;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Whether to use mojos for amounts instead of XCH.
    #[arg(long)]
    pub mojos: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initializes the config file with your wallet's key.
    Init {
        #[clap(flatten)]
        key: CliKey,

        /// The uri of a trusted full node, such as `localhost:8444`.
        #[arg(long, short = 'n')]
        node_uri: Option<String>,

        /// The name of the network which the full node is connected to.
        #[arg(long)]
        network_id: Option<String>,

        /// The genesis challenge of the network, found with `chia show -s`.
        #[arg(long)]
        agg_sig_data: Option<String>,
    },

    /// Generates a spend bundle for a single payment.
    Send {
        /// The bech32m encoded address or puzzle hash to send to.
        address: String,

        /// The amount to send. Defaults to XCH unless you specify `--mojos`.
        amount: f64,

        /// The network fee. Defaults to XCH unless you specify `--mojos`.
        #[arg(long, short = 'f')]
        fee: f64,
    },

    /// Signs the coin spends in a spend bundle in-place.
    Sign {
        /// The file containing the spend bundle that needs to be signed.
        spend_bundle: String,

        /// The derivation index to which it's necessary to sync the wallet to.
        #[arg(long, short = 'i')]
        derivation_index: u32,
    },

    /// Submits a signed spend bundle to the network's mempool.
    Push {
        /// The file containing the signed spend bundle.
        spend_bundle: String,
    },
}
