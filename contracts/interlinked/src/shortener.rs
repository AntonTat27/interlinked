use soroban_sdk::{contract, contractimpl, symbol_short, Env, Bytes, BytesN, Map, String};

#[contract]
pub struct LinkShortener;

#[contractimpl]
impl LinkShortener {
    pub fn shortened(env: Env, merchant: String, url: String) -> String {
        let mut storage: Map<String, String> = env.storage().persistent().get(&merchant).unwrap_or(Map::new(&env));
        let url_key: String = url.slice(8);

        storage.set(merchant.clone(), url);
        env.storage().persistent().set(&symbol_short!("links"), &storage);
        merchant
    }

    pub fn resolve(env: Env, hash: BytesN<32>) -> Option<String> {
        let storage: Map<BytesN<32>, String> = env.storage().persistent().get(&symbol_short!("links")).unwrap_or(Map::new(&env));
        storage.get(hash)
    }
}
