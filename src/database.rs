use chia_bls::{DerivableKey, PublicKey, SecretKey};
use chia_wallet::{
    standard::{standard_puzzle_hash, DEFAULT_HIDDEN_PUZZLE_HASH},
    DeriveSynthetic,
};
use chia_wallet_sdk::{DerivationStore, Signer};
use sqlx::{Sqlite, SqlitePool, Transaction};

use crate::keys::WalletKey;

pub struct WalletDb {
    pool: SqlitePool,
    key: WalletKey,
}

impl WalletDb {
    pub async fn new(path: &str, key: WalletKey) -> Result<Self, sqlx::Error> {
        let pool = SqlitePool::connect(path).await?;
        sqlx::migrate!().run(&pool).await?;
        Ok(Self { pool, key })
    }

    async fn insert_derivation(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        index: u32,
    ) -> Result<(), sqlx::Error> {
        match &self.key {
            WalletKey::SecretKey(sk) => {
                let secret_key = sk
                    .derive_unhardened(index)
                    .derive_synthetic(&DEFAULT_HIDDEN_PUZZLE_HASH);
                self.insert_sk_derivation(tx, secret_key, index).await
            }
            WalletKey::PublicKey(pk) => {
                let public_key = pk
                    .derive_unhardened(index)
                    .derive_synthetic(&DEFAULT_HIDDEN_PUZZLE_HASH);
                self.insert_pk_derivation(tx, public_key, index).await
            }
        }
    }

    async fn insert_sk_derivation(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        secret_key: SecretKey,
        index: u32,
    ) -> Result<(), sqlx::Error> {
        let public_key = secret_key.public_key();
        let puzzle_hash = standard_puzzle_hash(&public_key).to_vec();

        let public_key = public_key.to_bytes().to_vec();
        let secret_key = secret_key.to_bytes().to_vec();

        sqlx::query!(
            "
            INSERT OR IGNORE INTO `derivations` (
                `derivation_index`,
                `secret_key`,
                `public_key`,
                `puzzle_hash`
            ) VALUES (?, ?, ?, ?)
            ",
            index,
            secret_key,
            public_key,
            puzzle_hash
        )
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    async fn insert_pk_derivation(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        public_key: PublicKey,
        index: u32,
    ) -> Result<(), sqlx::Error> {
        let puzzle_hash = standard_puzzle_hash(&public_key).to_vec();
        let public_key = public_key.to_bytes().to_vec();

        sqlx::query!(
            "
            INSERT OR IGNORE INTO `derivations` (
                `derivation_index`,
                `public_key`,
                `puzzle_hash`
            ) VALUES (?, ?, ?)
            ",
            index,
            public_key,
            puzzle_hash
        )
        .execute(&mut **tx)
        .await?;

        Ok(())
    }
}

impl DerivationStore for WalletDb {
    async fn derivations(&self) -> u32 {
        let row = sqlx::query!(
            "
            SELECT MAX(`derivation_index`) AS `max_derivation` FROM `derivations`
            "
        )
        .fetch_one(&self.pool)
        .await
        .unwrap();

        row.max_derivation
            .map(|index| index + 1)
            .unwrap_or_default() as u32
    }

    async fn public_key(&self, index: u32) -> Option<PublicKey> {
        let row = sqlx::query!(
            "
            SELECT `public_key` FROM `derivations` WHERE `derivation_index` = ?
            ",
            index
        )
        .fetch_optional(&self.pool)
        .await
        .unwrap()?;

        let bytes = row.public_key.try_into().unwrap();
        let pk = PublicKey::from_bytes(&bytes).unwrap();
        Some(pk)
    }

    async fn puzzle_hash(&self, index: u32) -> Option<[u8; 32]> {
        let row = sqlx::query!(
            "
            SELECT `puzzle_hash` FROM `derivations` WHERE `derivation_index` = ?
            ",
            index
        )
        .fetch_optional(&self.pool)
        .await
        .unwrap()?;

        let puzzle_hash = row.puzzle_hash.try_into().unwrap();
        Some(puzzle_hash)
    }

    async fn index_of_puzzle_hash(&self, puzzle_hash: [u8; 32]) -> Option<u32> {
        let puzzle_hash = puzzle_hash.to_vec();

        let row = sqlx::query!(
            "
            SELECT `derivation_index` FROM `derivations` WHERE `puzzle_hash` = ?
            ",
            puzzle_hash
        )
        .fetch_optional(&self.pool)
        .await
        .unwrap()?;

        Some(row.derivation_index as u32)
    }

    async fn derive_to_index(&self, index: u32) {
        let mut tx = self.pool.begin().await.unwrap();

        let row = sqlx::query!(
            "
            SELECT MAX(`derivation_index`) AS `max_derivation` FROM `derivations`
            "
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();

        let derivations = row
            .max_derivation
            .map(|index| index + 1)
            .unwrap_or_default() as u32;

        for index in derivations..index {
            self.insert_derivation(&mut tx, index).await.unwrap();
        }

        tx.commit().await.unwrap();
    }
}

impl Signer for WalletDb {
    async fn secret_key(&self, public_key: &PublicKey) -> Option<SecretKey> {
        let public_key = public_key.to_bytes().to_vec();

        let row = sqlx::query!(
            "
            SELECT `secret_key` FROM `derivations` WHERE `public_key` = ?
            ",
            public_key
        )
        .fetch_optional(&self.pool)
        .await
        .unwrap()?;

        let bytes = row.secret_key?.try_into().unwrap();
        let sk = SecretKey::from_bytes(&bytes).unwrap();
        Some(sk)
    }
}
