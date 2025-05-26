use crate::shortener::Shortener;
use crate::storage::{BASE_URL, PUBLIC_KEY, WEB_AUT_CREDENTIALS};
use crate::upgrade::UpgradeableContract;
use soroban_sdk::{contract, contractimpl, BytesN, Env, String};

#[contract]
pub struct LinkShortener;

#[contractimpl]
impl LinkShortener {
    pub fn __constructor(e: Env, base_url: String, public_key: BytesN<65>, credentials: String) {
        e.storage().persistent().set(&BASE_URL, &base_url);
        e.storage().persistent().set(&PUBLIC_KEY, &public_key);
        e.storage()
            .persistent()
            .set(&WEB_AUT_CREDENTIALS, &credentials);
    }

    pub fn shortened(env: Env, url: String) -> String {
        //env.current_contract_address().require_auth();

        Shortener::shortened(env, url)
    }

    /// Upgrade smart contract
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        UpgradeableContract::upgrade(env, new_wasm_hash)
    }

    pub fn extend_ttl(env: Env) {
        let max_ttl = env.storage().max_ttl();

        env.storage()
            .persistent()
            .extend_ttl(&BASE_URL, max_ttl, max_ttl);
        env.storage()
            .persistent()
            .extend_ttl(&PUBLIC_KEY, max_ttl, max_ttl);
        env.storage()
            .persistent()
            .extend_ttl(&WEB_AUT_CREDENTIALS, max_ttl, max_ttl);
    }
}
