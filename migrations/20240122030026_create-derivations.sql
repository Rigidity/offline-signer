CREATE TABLE `derivations` (
    `derivation_index` INT NOT NULL PRIMARY KEY,
    `secret_key` BLOB,
    `public_key` BLOB NOT NULL,
    `puzzle_hash` BLOB NOT NULL
)
