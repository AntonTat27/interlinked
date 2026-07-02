use crate::error::Error;
use crate::storage::{ApiKeyV1, APIKEY_V1};
use soroban_sdk::{Env, Map, String};

pub struct ApiKey;

impl ApiKey {
    pub fn set_api_key_v1(env: Env, key: String, access: u32, ttl: u32) -> Result<(), Error> {
        let storage = env.storage().persistent();
        // If an api key v1 exists, get it
        let mut key_to_store =
            if let Some(keys) = storage.get::<_, Map<String, ApiKeyV1>>(&APIKEY_V1) {
                keys
            } else {
                soroban_sdk::Map::new(&env)
            };

        let new_key = ApiKeyV1 {
            access,
            ttl,
            attributes: None,
        };
        key_to_store.set(key, new_key);
        env.storage().persistent().set(&APIKEY_V1, &key_to_store);
        Ok(())
    }

    pub fn delete_api_key_v1(env: Env, key: String) -> Result<(), Error> {
        let storage = env.storage().persistent();
        let mut key_to_store =
            if let Some(keys) = storage.get::<_, Map<String, ApiKeyV1>>(&APIKEY_V1) {
                keys
            } else {
                return Ok(())
            };
        key_to_store.remove(key);
        env.storage().persistent().set(&APIKEY_V1, &key_to_store);
        Ok(())
    }
}
