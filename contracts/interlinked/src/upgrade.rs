use soroban_sdk::{BytesN, Env, String};

pub struct UpgradeableContract;

impl UpgradeableContract {

    pub fn version_build(env: Env) -> String {
        String::from_str(&env, "0.0.1")
    }

    pub fn version() -> i32 {
        3
    }

    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}