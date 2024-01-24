use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use chia_protocol::Program;
use clvmr::{
    serde::{node_from_bytes, node_to_bytes},
    Allocator, FromNodePtr, ToNodePtr,
};
use home::home_dir;

pub struct Paths {
    pub ssl_dir: PathBuf,
    pub db_dir: PathBuf,
    pub config: PathBuf,
}

impl Paths {
    pub fn new() -> Self {
        let app_dir = home_dir().unwrap().join(".offline-signer");
        create_dir(app_dir.as_path());

        let ssl_dir = app_dir.join("ssl");
        create_dir(ssl_dir.as_path());

        let db_dir = app_dir.join("db");
        create_dir(db_dir.as_path());

        let config = app_dir.join("config.json");

        Self {
            ssl_dir,
            db_dir,
            config,
        }
    }
}

pub fn bytes_to_program(bytes: Vec<u8>) -> Program {
    let mut a = Allocator::new();
    let ptr = node_from_bytes(&mut a, &bytes).unwrap();
    Program::from_node_ptr(&a, ptr).unwrap()
}

pub fn program_to_bytes(program: Program) -> Vec<u8> {
    let mut a = Allocator::new();
    let ptr = program.to_node_ptr(&mut a).unwrap();
    node_to_bytes(&a, ptr).unwrap()
}

pub fn path_exists(path: &Path) -> bool {
    path.try_exists()
        .unwrap_or_else(|_| panic!("could not access {}", path.to_str().unwrap()))
}

pub fn create_dir(path: &Path) {
    if !path_exists(path) {
        fs::create_dir(path)
            .unwrap_or_else(|_| panic!("could not create directory {}", path.to_str().unwrap()));
    }
}

pub fn program_name() -> Option<String> {
    std::env::current_exe()
        .ok()
        .as_ref()
        .map(Path::new)
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)
        .map(String::from)
}

pub fn strip_prefix(puzzle_hash: &str) -> &str {
    if let Some(puzzle_hash) = puzzle_hash.strip_prefix("0x") {
        puzzle_hash
    } else if let Some(puzzle_hash) = puzzle_hash.strip_prefix("0X") {
        puzzle_hash
    } else {
        puzzle_hash
    }
}

pub fn amount_as_mojos(amount: f64, is_mojos: bool) -> u64 {
    if is_mojos {
        amount as u64
    } else {
        (amount * 1.0e12) as u64
    }
}
