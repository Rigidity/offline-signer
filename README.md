# Offline Signer

[![crate](https://img.shields.io/crates/v/offline-signer.svg)](https://crates.io/crates/offline-signer)
[![minimum rustc 1.75](https://img.shields.io/badge/rustc-1.75+-red.svg)](https://rust-lang.github.io/rfcs/2495-min-rust-version.html)

This is an unofficial CLI wallet application for the [Chia blockchain](https://chia.net). It's built from the ground up using the [wallet SDK library](https://github.com/Rigidity/chia-wallet-sdk), and allows you to create transactions using only your public key, and sign them offline on a different machine, using only the private key and no full node.

## Disclaimer

This project is experimental and a work in progress. It has not yet been rigorously tested in a production environment. Use on mainnet only at your own risk, and verify transactions before submitting them to the network.

I am not to be held responsible for any misuse of this application. Please do **not** use it, if you are not okay with things breaking.

That said, contributions and any help testing it are appreciated.

## Installation

You will first need to install the Rust toolchain, by running the command on the [Rustup](https://rustup.rs) website.

Then, run the following command to install the offline signer CLI:

```bash
cargo install offline-signer
```

You can see a list of commands with:

```bash
offline-signer help
```

## Setup Cold Wallet

You can find your wallet's root public key using this command:

```bash
chia keys show
```

To set up the cold wallet, connected to your local mainnet full node:

```bash
offline-signer init --public-key '<pk>' --node-uri localhost:8444
```

To set it up using the simulator (using your own port):

```bash
offline-signer init --public-key '<pk>' --node-uri localhost:54939 --network-id simulator0
```

Note that the `--agg-sig-data` is the same as the mainnet genesis challenge when using the simulator, and you will not need to override it. However on testnet, you will need to set it to the appropriate genesis challenge found with `chia show -s`.

## Setup Signer

You can find your wallet's mnemonic using this command:

```bash
chia keys show --show-mnemonic-phrase
```

To set up the signer, offline from the network:

```bash
offline-signer init --mnemonic '<phrase>'
```

You can also use your root secret key instead of the mnemonic if you prefer:

```bash
offline-signer init --secret-key '<sk>'
```

Note that you cannot create new transactions using this setup, since you have not connected a node.

## Create Transaction

You can create a transaction with:

```bash
offline-signer send <address> <amount> --fee <fee>
```

Note that this will use amounts formatted in XCH by default, unless you specify `--mojos` explicitly.

You can pipe this to a spend bundle file:

```bash
offline-signer send ... > spend.json
```

Keep track of the derivation index, so that you know how many keys need to be derived when signing the transaction.

## Sign Transaction

You can sign an unsigned spend bundle file:

```bash
offline-signer sign spend.json --derivation-index <index>
```

Note that this will update the spend bundle file in place with the new signature.

The derivation index is required, because the wallet cannot sync against the full node directly to figure it out on its own.

## Submit Transaction

Once you've signed the spend bundle, you can submit it to the network's mempool:

```bash
offline-signer push spend.json
```

This can take a while to complete, depending on the fee you used when creating the transaction.
