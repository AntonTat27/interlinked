use crate::error::Error;
use crate::storage::{AccessPolicy, DisposableLinkInfo, GatedLinkInfo, LinkInfo, StorageKey,
                     BASE_URL, LAST_DISPOSABLE, LAST_GATED, LAST_SHORT, LAST_TEMPORARY};
use soroban_sdk::crypto::bls12_381::Bls12381Fr;
use soroban_sdk::unwrap::UnwrapOptimized;
use soroban_sdk::{Bytes, BytesN, Env, EnvBase, String, Symbol, Val};

pub struct Shortener;

impl Shortener {
    const SHORTCODE_BUFFER_SIZE: usize = 12;
    const FULL_URL_BUFFER_SIZE: usize = 32;

    fn get_dict(env: &Env) -> Bytes {
        Bytes::from_slice(&env, "abcdefghijklmnopqrstuvwxyz0123456789".as_bytes())
    }

    fn get_last_shortcode(env: &Env, last: Symbol) -> String {
        env.storage()
            .persistent()
            .get(&last)
            .unwrap_or(String::from_str(env, "a"))
    }

    fn generate_next_shortcode(
        env: &Env,
        key: &Symbol,
        prefix: String,
        last_code: String,
        symbols: &Bytes,
    ) -> Result<String, Error> {
        let last_link: &mut [u8; Self::SHORTCODE_BUFFER_SIZE] =
            &mut [0u8; Self::SHORTCODE_BUFFER_SIZE];
        let mut len: usize;

        len = last_code.len() as usize;
        let last_shortness_slice: &mut [u8; Self::SHORTCODE_BUFFER_SIZE] =
            &mut [0u8; Self::SHORTCODE_BUFFER_SIZE];
        env.string_copy_to_slice(
            last_code.to_object(),
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

        // store last asset used
        let short_last = core::str::from_utf8(&last_link[..len])
            .map_err(|_| "Failed to convert &[u8] to &str")
            .unwrap();
        env.storage().persistent().set(key, &short_last);

        // Convert Symbol to String using the function
        if prefix.len() == 1 {
            let code_s: &mut [u8; Self::SHORTCODE_BUFFER_SIZE + 1] =
                &mut [0u8; Self::SHORTCODE_BUFFER_SIZE + 1];
            env.string_copy_to_slice(prefix.to_object(), Val::U32_ZERO, code_s[..1].as_mut())
                .unwrap_optimized();

            let len = short_last.len();
            env.string_copy_to_slice(
                String::from_str(&env, short_last).to_object(),
                Val::U32_ZERO,
                code_s[1..len + 1].as_mut(),
            )
            .unwrap_optimized();
            return Ok(String::from_str(
                &env,
                core::str::from_utf8(&code_s[..len + 1])
                    .map_err(|_| "Failed to convert &[u8] to &str")
                    .unwrap(),
            ));
        } else if prefix.len() > 0 {
            return Err(Error::TooLong);
        }

        let code_s = core::str::from_utf8(&last_link[..len])
            .map_err(|_| "Failed to convert &[u8] to &str")
            .unwrap();

        Ok(String::from_str(&env, code_s))
    }

    fn generate_full_url(env: &Env, code_link: &String) -> String {
        let base_url = env
            .storage()
            .persistent()
            .get(&BASE_URL)
            .unwrap_or(String::from_str(env, "base_url"));

        let short_url: &mut [u8; Self::FULL_URL_BUFFER_SIZE] =
            &mut [0u8; Self::FULL_URL_BUFFER_SIZE];
        let prefix_len = base_url.len() as usize;
        env.string_copy_to_slice(
            base_url.to_object(),
            Val::U32_ZERO,
            short_url[..prefix_len].as_mut(),
        )
        .unwrap_optimized();

        let len = code_link.len() as usize;
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
    pub fn shortened(env: Env, url: String, content_type: String) -> String {
        let symbols = Self::get_dict(&env);
        // Get and increment the last used short code
        let last_shortcode = Self::get_last_shortcode(&env, LAST_SHORT);
        let code_link = Self::generate_next_shortcode(
            &env,
            &LAST_SHORT,
            String::from_str(&env, ""),
            last_shortcode,
            &symbols,
        )
        .unwrap();

        // check if the code is already used
        // todo: how to avoid that
        if env
            .storage()
            .persistent()
            .has(&StorageKey::DstLink(code_link.clone()))
        {
            return String::from_str(&env, "");
        }

        let dst_key = &LinkInfo {
            dest: url,
            is_active: true,
            content_type,
        };
        env.storage()
            .persistent()
            .set(&StorageKey::DstLink(code_link.clone()), dst_key);
        Self::generate_full_url(&env, &code_link)
    }

    pub fn shortened_ext(env: Env, url: String, url_code: String, content_type: String) -> String {
        let dst_key = &LinkInfo {
            dest: url,
            is_active: true,
            content_type,
        };
        env.storage()
            .persistent()
            .set(&StorageKey::DstLink(url_code.clone()), dst_key);
        let base_url: String = env
            .storage()
            .persistent()
            .get(&BASE_URL)
            .unwrap_or(String::from_str(&env, "base_url"));

        let short_url: &mut [u8; Self::FULL_URL_BUFFER_SIZE] =
            &mut [0u8; Self::FULL_URL_BUFFER_SIZE];
        let prefix_len = base_url.len() as usize;
        env.string_copy_to_slice(
            base_url.to_object(),
            Val::U32_ZERO,
            short_url[..prefix_len].as_mut(),
        )
        .unwrap_optimized();

        let len = url_code.len() as usize;
        env.string_copy_to_slice(
            url_code.clone().to_object(),
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

    pub fn temporary_link(env: Env, url: String, content_type: String) -> String {
        let symbols = Self::get_dict(&env);
        let last_shortcode = Self::get_last_shortcode(&env, LAST_TEMPORARY);
        let code_link = Self::generate_next_shortcode(
            &env,
            &LAST_TEMPORARY,
            String::from_str(&env, "-"),
            last_shortcode,
            &symbols,
        )
        .unwrap();

        let dst_key = &LinkInfo {
            dest: url,
            is_active: true,
            content_type,
        };
        env.storage()
            .temporary()
            .set(&StorageKey::DstLink(code_link.clone()), dst_key);

        Self::generate_full_url(&env, &code_link)
    }

    pub fn init_disposable_link(
        env: Env,
        salt: Bytes,
        failed_attempts: u32,
        content_type: String,
        sk: Bls12381Fr,
    ) -> (BytesN<96>, String) {
        let symbols = Self::get_dict(&env);

        let last_shortcode = Self::get_last_shortcode(&env, LAST_DISPOSABLE);

        let code_link = Self::generate_next_shortcode(
            &env,
            &LAST_DISPOSABLE,
            String::from_str(&env, "~"),
            last_shortcode,
            &symbols,
        )
        .unwrap();

        let dst: &mut [u8; Self::SHORTCODE_BUFFER_SIZE + 1] =
            &mut [0u8; Self::SHORTCODE_BUFFER_SIZE + 1];
        let signed_salt =
            Self::sign_message(&env, salt.clone(), Bytes::from_slice(&env, dst), sk.clone());

        let dst_key = &DisposableLinkInfo {
            dest: String::from_str(&env, ""),
            is_active: false,
            content_type,
            signed_salt,
            failed_attempts,
            failed_retries: 0,
            success_attempts: 1,
            success_retries: 0,
        };

        env.storage()
            .temporary()
            .set(&StorageKey::DstLink(code_link.clone()), dst_key);

        let len = code_link.len() as usize;
        env.string_copy_to_slice(code_link.to_object(), Val::U32_ZERO, dst[..len].as_mut())
            .unwrap_optimized();

        let key = Self::sign_message(&env, salt, Bytes::from_slice(&env, dst), sk);

        (key, code_link)
    }

    pub fn disposable_link(env: Env, code_link: String, url: String) -> Result<String, Error> {
        let mut link_info: DisposableLinkInfo = match env
            .storage()
            .temporary()
            .get(&StorageKey::DstLink(code_link.clone()))
        {
            Some(info) => info,
            None => return Err(Error::NotInitiated),
        };

        if !link_info.is_active && link_info.failed_retries >= link_info.failed_attempts {
            return Err(Error::DisposedErr);
        } else if !link_info.is_active
            && link_info.failed_retries < link_info.failed_attempts
            && link_info.dest.len() > 0
        {
            return Err(Error::DisposedOk);
        } else if link_info.is_active {
            return Err(Error::AlreadyInitiated);
        }

        link_info.dest = url;
        link_info.is_active = true;

        env.storage()
            .temporary()
            .set(&StorageKey::DstLink(code_link.clone()), &link_info);

        Ok(Self::generate_full_url(&env, &code_link))
    }

    pub fn resolve_disposable_link(
        env: Env,
        code_link: String,
        salt: Bytes,
        sk: Bls12381Fr,
    ) -> Result<(BytesN<96>, String), Error> {
        let mut link_info: DisposableLinkInfo = match env
            .storage()
            .temporary()
            .get(&StorageKey::DstLink(code_link.clone()))
        {
            Some(info) => info,
            None => return Err(Error::NotInitiated),
        };
        if !link_info.is_active && link_info.failed_retries >= link_info.failed_attempts {
            return Err(Error::DisposedErr);
        } else if !link_info.is_active
            && link_info.failed_retries < link_info.failed_attempts
            && link_info.dest.len() > 0
        {
            return Err(Error::DisposedOk);
        } else if !link_info.is_active && link_info.dest.len() == 0 {
            return Err(Error::NotInitiated);
        }

        let dst: &mut [u8; Self::SHORTCODE_BUFFER_SIZE + 1] =
            &mut [0u8; Self::SHORTCODE_BUFFER_SIZE + 1];
        let signed_salt =
            Self::sign_message(&env, salt.clone(), Bytes::from_slice(&env, dst), sk.clone());
        if signed_salt != link_info.signed_salt {
            link_info.failed_retries += 1;
            if link_info.failed_retries >= link_info.failed_attempts {
                link_info.dest = String::from_str(&env, "disposed_err");
                link_info.is_active = false;
            }
            env.storage()
                .temporary()
                .set(&StorageKey::DstLink(code_link.clone()), &link_info);
            return Ok((
                link_info.signed_salt,
                String::from_str(&env, ""),
            ));
        }
        link_info.dest = String::from_str(&env, "disposed_ok");
        link_info.is_active = false;
        env.storage()
            .temporary()
            .set(&StorageKey::DstLink(code_link.clone()), &link_info);

        let len = code_link.len() as usize;
        env.string_copy_to_slice(code_link.to_object(), Val::U32_ZERO, dst[..len].as_mut())
            .unwrap_optimized();
        let key = Self::sign_message(&env, salt, Bytes::from_slice(&env, dst), sk);

        Ok((key, link_info.content_type))
    }

    pub fn create_gated_link(
        env: Env,
        url: String,
        content_type: String,
        policy: AccessPolicy,
    ) -> Result<String, Error> {
        let symbols = Self::get_dict(&env);
        let last_shortcode = Self::get_last_shortcode(&env, LAST_GATED);
        let code_link = Self::generate_next_shortcode(
            &env,
            &LAST_GATED,
            String::from_str(&env, "!"),
            last_shortcode,
            &symbols,
        )?;

        if env
            .storage()
            .persistent()
            .has(&StorageKey::GatedLink(code_link.clone()))
        {
            return Err(Error::AlreadyInitiated);
        }

        let gated_info = &GatedLinkInfo {
            dest: url,
            is_active: true,
            content_type,
            policy,
        };
        env.storage()
            .persistent()
            .set(&StorageKey::GatedLink(code_link.clone()), gated_info);

        Ok(Self::generate_full_url(&env, &code_link))
    }

    fn sign_message(env: &Env, message: Bytes, dst: Bytes, sk: Bls12381Fr) -> BytesN<96> {
        let crypto = env.crypto();
        let bls = crypto.bls12_381();
        let hash = bls.hash_to_g1(&message, &dst);
        let signature = bls.g1_mul(&hash, &sk);
        signature.to_bytes()
    }

    pub fn extend_link_ttl(
        env: Env,
        code_link: String,
        threshold: u32,
        duration: u32,
    ) -> Result<(), Error> {
        let code_s: &mut [u8; Self::SHORTCODE_BUFFER_SIZE + 1] =
            &mut [0u8; Self::SHORTCODE_BUFFER_SIZE + 1];
        let len = code_link.len() as usize;
        env.string_copy_to_slice(code_link.to_object(), Val::U32_ZERO, code_s[..len].as_mut())
            .unwrap_optimized();
        if code_s[0] != b'~' && code_s[0] != b'-' {
            if env
                .storage()
                .persistent()
                .has(&StorageKey::DstLink(code_link.clone()))
            {
                env.storage().persistent().extend_ttl(
                    &StorageKey::DstLink(code_link.clone()),
                    threshold,
                    threshold + duration,
                );
            }
        } else if code_s[0] == b'-'  || code_s[0] == b'~' {
            if env
                .storage()
                .temporary()
                .has(&StorageKey::DstLink(code_link.clone()))
            {
                env.storage().temporary().extend_ttl(
                    &StorageKey::DstLink(code_link.clone()),
                    threshold,
                    threshold + duration,
                );
            }
        } else {
            return Err(Error::NotSupported);
        }

        Ok(())
    }
    pub fn delete_link(env: Env, code_link: String) -> Result<(), Error> {
        let code_s: &mut [u8; Self::SHORTCODE_BUFFER_SIZE + 1] =
            &mut [0u8; Self::SHORTCODE_BUFFER_SIZE + 1];
        let len = code_link.len() as usize;
        env.string_copy_to_slice(code_link.to_object(), Val::U32_ZERO, code_s[..len].as_mut())
            .unwrap_optimized();
        if code_s[0] != b'~' && code_s[0] != b'-' {
            if env
                .storage()
                .persistent()
                .has(&StorageKey::DstLink(code_link.clone()))
            {
                env.storage().persistent().remove(
                    &StorageKey::DstLink(code_link.clone()));
            }
        } else if code_s[0] == b'-'  || code_s[0] == b'~' {
            if env
                .storage()
                .temporary()
                .has(&StorageKey::DstLink(code_link.clone()))
            {
                env.storage().temporary().remove(
                    &StorageKey::DstLink(code_link.clone()));
            }
        } else {
            return Err(Error::NotSupported);
        }
        Ok(())
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
