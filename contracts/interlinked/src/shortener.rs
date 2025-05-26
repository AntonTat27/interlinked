use crate::storage::{LinkInfo, StorageKey, BASE_URL, LAST_SHORT, REDIRECT_LINK};
use soroban_sdk::unwrap::UnwrapOptimized;
use soroban_sdk::{symbol_short, Bytes, BytesN, Env, EnvBase, Map, String, Val};

pub struct Shortener;

impl Shortener {
    pub fn shortened(env: Env, url: String) -> String {
        let symbols = Bytes::from_slice(&env, "abcdefghijklmnopqrstuvwxyz0123456789".as_bytes());

        let last_link: &mut [u8; 12] = &mut [0u8; 12];
        let mut len: usize;
        let last_shortness: String = env
            .storage()
            .persistent()
            .get(&LAST_SHORT)
            .unwrap_or(String::from_str(&env, "a"));

        len = last_shortness.len() as usize;
        let last_shortness_slice: &mut [u8; 12] = &mut [0u8; 12];
        env.string_copy_to_slice(
            last_shortness.to_object(),
            Val::U32_ZERO,
            last_shortness_slice[..len].as_mut(),
        )
        .unwrap_optimized();
        let mut current_string = <Bytes>::from_slice(&env, &last_shortness_slice[..len]);
        increment_string(&mut current_string, &symbols);

        len = current_string.len() as usize;
        env.bytes_copy_to_slice(
            current_string.to_object(),
            Val::U32_ZERO,
            last_link[..len].as_mut(),
        )
        .unwrap_optimized();

        // Convert Symbol to String using the function

        let code_s = core::str::from_utf8(&last_link[..len])
            .map_err(|_| "Failed to convert &[u8] to &str")
            .unwrap();
        let code_link = String::from_str(&env, code_s);
        let dst_key = &LinkInfo {
            dest: url,
            is_active: true,
            link_type: REDIRECT_LINK,
        };
        env.storage()
            .persistent()
            .set(&StorageKey::DstLink(code_link.clone()), dst_key);
        // store last asset used
        let short_last = core::str::from_utf8(&last_link[..len])
            .map_err(|_| "Failed to convert &[u8] to &str")
            .unwrap();

        let short_symbol = String::from_str(&env, short_last);
        env.storage().persistent().set(&LAST_SHORT, &short_symbol);

        let base_url: String = env
            .storage()
            .persistent()
            .get(&BASE_URL)
            .unwrap_or(String::from_str(&env, "base_url"));

        let short_url: &mut [u8; 32] = &mut [0u8; 32];
        let prefix_len = base_url.len() as usize;
        env.string_copy_to_slice(
            base_url.to_object(),
            Val::U32_ZERO,
            short_url[..prefix_len].as_mut(),
        )
        .unwrap_optimized();

        len = code_link.len() as usize;
        env.string_copy_to_slice(
            code_link.clone().to_object(),
            Val::U32_ZERO,
            short_url[prefix_len..len + prefix_len].as_mut(),
        )
        .unwrap_optimized();

        String::from_str(
            &env,
            core::str::from_utf8(&short_url[..len + prefix_len])
                .map_err(|_| "Failed to convert &[u8] to &str")
                .unwrap(),
        )
    }

    pub fn resolve(env: Env, hash: BytesN<32>) -> Option<String> {
        let storage: Map<BytesN<32>, String> = env
            .storage()
            .persistent()
            .get(&symbol_short!("links"))
            .unwrap_or(Map::new(&env));
        storage.get(hash)
    }
}

fn increment_string(s: &mut Bytes, symbols: &Bytes) {
    let max_index = symbols.len() - 1;
    let mut increment_needed = true;
    let len = s.len();
    let mut idx = 0;

    while increment_needed && idx < len {
        if let Some(current_char) = symbols.iter().position(|c| c == s.get_unchecked(idx)) {
            if (current_char as u32) == max_index {
                s.set(idx, symbols.get_unchecked(0));
                if idx == len - 1 {
                    s.push_back(symbols.get_unchecked(0));
                }
            } else {
                s.set(idx, symbols.get_unchecked((current_char + 1) as u32));
                increment_needed = false;
            }
        }
        idx += 1;
    }
}
