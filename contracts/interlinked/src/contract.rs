use soroban_sdk::{contract, contractimpl, BytesN, Env, String};
use crate::shortener::Shortener;
use crate::storage::BASE_URL;
use crate::upgrade::UpgradeableContract;

#[contract]
pub struct LinkShortener;

#[contractimpl]
impl LinkShortener {
    pub fn __constructor(e: Env, base_url: String) {
        e.storage().persistent().set(&BASE_URL, &base_url);
    }
    pub fn shortened(env: Env, merchant: String, url: String) -> String {
        Shortener::shortened(env, merchant, url)
    }
    /// Upgrade smart contract
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        UpgradeableContract::upgrade(env, new_wasm_hash)
    }
}