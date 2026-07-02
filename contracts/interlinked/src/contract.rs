use crate::api_key::ApiKey;
use crate::error::Error;
use crate::shortener::Shortener;
use crate::storage::{
    AccessPolicy, GatedLinkInfo, StorageKey, ADMIN, APIKEY_V1, BASE_URL, LAST_DISPOSABLE,
    LAST_SHORT, LAST_TEMPORARY, PUBLIC_KEY, WEB_AUT_CREDENTIALS,
};
use crate::upgrade::UpgradeableContract;
use crate::zk_verifier::ZkVerifier;
use soroban_sdk::crypto::bls12_381::Bls12381Fr;
use soroban_sdk::unwrap::UnwrapOptimized;
use soroban_sdk::{
    contract, contractimpl, Address, Bytes, BytesN, Env, EnvBase, String, Val, Vec,
};

#[contract]
pub struct LinkShortener;

#[contractimpl]
impl LinkShortener {
    pub fn __constructor(e: Env, base_url: String, admin: Address) {
        e.storage().persistent().set(&BASE_URL, &base_url);
        e.storage().persistent().set(&ADMIN, &admin);
    }

    /// Sets the administrator address in persistent storage.
    ///
    /// # Arguments
    ///
    /// * `e` - An instance of the `Env` structure, providing access to the
    ///     environment and storage.
    /// * `admin` - The `Address` of the administrator to be set.
    ///
    /// This function stores the provided `admin` address into persistent storage
    /// under the predefined key `ADMIN`. The administrator address is typically
    /// used to identify and grant special privileges to a specific user or account.
    ///
    /// # Example
    ///
    /// ```rust
    /// set_admin(env, admin_address);
    /// ```
    pub fn set_admin(e: Env, admin: Address) {
        e.storage().persistent().set(&ADMIN, &admin);
    }

    /// Stores the web authentication credentials and the associated public key in persistent storage.
    ///
    /// # Parameters
    /// - `e`: An instance of the `Env` type, which provides access to the Stellar environment
    ///        and storage capabilities.
    /// - `public_key`: A `BytesN<65>` type representing the public key used for authentication,
    ///                 which is stored persistently.
    /// - `credentials`: A `String` containing the web authentication credentials,
    ///                   which will also be stored persistently.
    ///
    /// # Functionality
    /// - The function stores the provided `public_key` in persistent storage using the key `PUBLIC_KEY`.
    /// - Similarly, the `credentials` are stored in persistent storage using the key `WEB_AUT_CREDENTIALS`.
    ///
    /// # Storage
    /// - Both the public key and credentials are stored as persistent data, ensuring they are saved
    ///   across sessions and remain accessible unless explicitly removed.
    ///
    /// # Example
    /// ```
    /// set_web_auth_credentials(e, public_key, credentials);
    /// ```
    /// Here, `e` is the Stellar environment instance, `public_key` is the user's public key,
    /// and `credentials` contain authentication data for web access.
    ///
    /// # Notes
    /// - Ensure the appropriate storage keys (`PUBLIC_KEY` and `WEB_AUT_CREDENTIALS`) are
    ///   correctly defined before using this function.
    /// - This function assumes that the `Env` environment and the key-value storage system
    ///   have been properly set up.
    pub fn set_web_auth_credentials(e: Env, public_key: BytesN<65>, credentials: String) {
        e.storage().persistent().set(&PUBLIC_KEY, &public_key);
        e.storage()
            .persistent()
            .set(&WEB_AUT_CREDENTIALS, &credentials);
    }

    /// Shortens a given URL using the `Shortener` utility.
    ///
    /// # Arguments
    ///
    /// * `env` - The environment object, providing access to the current contract's context.
    /// * `url` - A string containing the URL that needs to be shortened.
    /// - `content_type`: a type of data stored in smart contract associated with the shortened URL.
    ///
    /// # Returns
    ///
    /// A `String` that represents the shortened version of the input URL.
    ///
    /// # Example
    ///
    /// ```
    /// let env = ...; // Initialize the environment object
    /// let original_url = String::from("https://example.com/some/long/path");
    /// let short_url = shortened(env, original_url);
    /// println!("{}", short_url); // Prints the shortened URL
    /// ```
    pub fn shortened(env: Env, url: String, content_type: String) -> String {
        //env.current_contract_address().require_auth();
        Shortener::shortened(env, url, content_type)
    }

    /// A function that generates a shortened external URL using a provided URL and a URL code.
    ///
    /// # Parameters
    ///
    /// - `env`: An instance of the `Env` environment, usually provided by the blockchain or runtime
    ///          context, that allows interaction with the contract environment.
    /// - `url`: A `String` representation of the full URL that needs to be shortened.
    /// - `url_code`: A `String` code that represents the desired shortened portion of the URL.
    /// - `content_type`: a type of data stored in smart contract associated with the shortened URL.
    ///
    /// # Returns
    ///
    /// - A `String` representing the shortened URL.
    ///
    /// # Note
    ///
    /// # Examples
    ///
    /// ```
    /// // Example usage:
    /// let shortened_url = shortened_ext(env, "https://example.com", "abc123".to_string());
    /// println!("Shortened URL: {}", shortened_url);
    /// ```
    pub fn shortened_ext(env: Env, url: String, url_code: String, content_type: String) -> String {
        //env.current_contract_address().require_auth();
        Shortener::shortened_ext(env, url, url_code, content_type)
    }

    /// Generates a temporary shortened link based on the provided URL.
    ///
    /// # Parameters
    /// - `env`: An instance of the environment (`Env`) that provides access to the contract's context and utilities.
    /// - `url`: A string containing the original URL to be shortened.
    /// - `content_type`: a type of data stored in smart contract associated with the shortened URL.
    ///
    /// # Returns
    /// - A `String` representing the generated temporary shortened URL.
    ///
    pub fn temporary_link(env: Env, url: String, content_type: String) -> String {
        //env.current_contract_address().require_auth();
        Shortener::temporary_link(env, url, content_type)
    }

    /// Initializes a disposable link with the specified environment, salt, and attempt count.
    ///
    /// # Arguments
    /// * `env` - The environment context in which the function operates.
    /// * `salt` - A unique `Bytes` value used to create variability in the link initialization process.
    /// * `failed_attempts` - The maximum number of allowed unsuccessful attempts to get
    /// stored data from a disposable link storage by resolve_disposable_link functions calls.
    /// The data will be disposed of after reaching the limit.
    /// - `content_type`: a type of data stored in smart contract associated with the shortened URL.
    ///
    /// # Returns
    /// A tuple consisting of:
    /// * `BytesN<96>` - A cryptographic value representing the base for encryption key
    /// * `String` - A string representation associated with the disposable link, for identification or usage.
    ///
    /// # Details
    /// The function generates a base for an encryption key using the address context obtained
    /// from the environment and the salt value provided. The generated key should be used
    /// to encrypt data before call of disposable_link function to store the encrypted data
    ///
    /// # Example
    /// ```
    /// let env = Env::default();
    /// let salt = Bytes::from("unique_salt");
    /// let failed_attempts = 3;
    /// let (link, identifier) = init_disposable_link(env, salt, failed_attempts);
    /// ```
    ///
    /// This function leverages reusable methods and internal logic to safely initialize a disposable link
    /// for limited-use scenarios, ensuring secure and unique link generation.
    pub fn init_disposable_link(
        env: Env,
        salt: Bytes,
        failed_attempts: u32,
        content_type: String,
    ) -> (BytesN<96>, String) {
        let sk = Self::private_key_from_address(&env);
        Shortener::init_disposable_link(env, salt, failed_attempts, content_type, sk)
    }

    /// Stores encrypted data in an initialized disposable link using the provided code link.
    ///
    /// This function is responsible for storing encrypted data in the temporary store. It takes
    /// an `Env` instance to access the Stellar smart contract environment and
    /// validate the operation context.
    ///
    /// # Arguments
    ///
    /// * `env` - The working environment for the Stellar smart contract. It provides
    ///   access to the current contract context and utility methods.
    /// * `code_link` - A `String` representing the base link that will be turned into
    ///   a disposable link.
    /// * `encrypted_data` - A `String` containing the encrypted payload/data that should be
    ///   stored into the disposable link.
    ///
    /// # Returns
    ///
    /// Returns a `Result` with:
    /// * `Ok(String)` - Contains the generated disposable link if the operation succeeds.
    /// * `Err(Error)` - Contains an error if the operation fails.
    ///
    /// # Remarks
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * the link is not initialized
    /// * the link already used to store encrypted data
    /// * the link is disposed after successful usage
    /// * the link is disposed after reaching a number of unsuccessful attempts
    pub fn disposable_link(
        env: Env,
        code_link: String,
        encrypted_data: String,
    ) -> Result<String, Error> {
        //env.current_contract_address().require_auth();
        Shortener::disposable_link(env, code_link, encrypted_data)
    }

    /// Resolves a disposable link, returning the associated data.
    ///
    /// # Parameters
    /// - `env`: The Stellar smart contract environment to operate in.
    /// - `code_link`: A `String` representing the disposable link or code to be resolved.
    /// - `salt`: A `Bytes` object used as an additional input for the resolution process.
    ///
    /// # Returns
    /// A `Result` which, on success, contains a tuple:
    /// - `BytesN<96>`: A 96-byte array that contains resolved data to form the encryption key.
    /// - `String`: Resolved encrypted data as a string value associated with the disposable link.
    ///
    /// On failure, it returns an `Error`.
    ///
    /// # How it works
    /// 1. Retrieves the private key associated with the current contract address by
    ///    invoking `private_key_from_address`.
    /// 2. Sign salt to verify that it was used by the same contract to generate base
    /// for an encryption key.
    ///
    /// # Errors
    /// This function will return an error if:
    /// * the link is not initialized
    /// * the link already used to store encrypted data
    /// * the link is disposed after successful usage
    /// * the link is disposed after reaching a number of unsuccessful attempts
    ///
    /// # Example Usage
    /// Assuming the environment `env` is set up correctly:
    /// ```
    /// let resolved_data = resolve_disposable_link(env, "abcd1234".to_string(), salt)?;
    /// ```
    pub fn resolve_disposable_link(
        env: Env,
        code_link: String,
        salt: Bytes,
    ) -> Result<(BytesN<96>, String), Error> {
        let sk = Self::private_key_from_address(&env);
        Shortener::resolve_disposable_link(env, code_link, salt, sk)
    }

    pub fn create_gated_link(
        env: Env,
        url: String,
        content_type: String,
        policy_hash: BytesN<32>,
        vk_id: String,
    ) -> Result<String, Error> {
        let policy = AccessPolicy { policy_hash, vk_id };
        Shortener::create_gated_link(env, url, content_type, policy)
    }

    pub fn resolve_gated_link(
        env: Env,
        code_link: String,
        proof_a: BytesN<96>,
        proof_b: BytesN<192>,
        proof_c: BytesN<96>,
        public_inputs: Vec<BytesN<32>>,
    ) -> Result<String, Error> {
        let info: GatedLinkInfo = env
            .storage()
            .persistent()
            .get(&StorageKey::GatedLink(code_link))
            .ok_or(Error::NotInitiated)?;

        ZkVerifier::verify_proof(&env, &info, proof_a, proof_b, proof_c, public_inputs)?;

        Ok(info.dest)
    }

    pub fn set_verifying_key(
        env: &Env,
        vk_id: String,
        alpha_g1: BytesN<96>,
        beta_g2: BytesN<192>,
        gamma_g2: BytesN<192>,
        delta_g2: BytesN<192>,
        ic: Vec<BytesN<96>>,
        nullifier_index: u32,
        policy_hash_index: Option<u32>,
        context_id_index: Option<u32>,
        is_member_index: Option<u32>,
    ) -> Result<(), Error> {
        ZkVerifier::register_verifying_key(
            env,
            vk_id,
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
            nullifier_index,
            policy_hash_index,
            context_id_index,
            is_member_index,
        )
    }

    /// Delete a link from smart contract by it code
    ///
    pub fn delete_link(env: Env, code_link: String) -> Result<(), Error> {
        Shortener::delete_link(env, code_link)
    }

    /// Extends the Time-To-Live (TTL) of a shortened link if certain conditions are met.
    ///
    /// # Parameters
    /// - `env`: The environment in which this operation is executed. This typically contains runtime
    ///   configurations or dependencies required to perform the TTL extension.
    /// - `code_link`: A `String` representing the shortened link's unique identifier or code whose TTL
    ///   is to be extended.
    /// - `threshold`: A `u32` value specifying the minimum number of ledger sequences
    ///   before the TTL extension can take place.
    /// - `duration`: A `u32` value representing the duration (in the ledger) by which
    /// the TTL should be extended.
    ///
    /// # Returns
    /// - `Ok(())`: Indicates that the TTL has been successfully extended or the operation was performed
    ///   without errors.
    /// - `Err(Error)`: An error occurring during the TTL extension process, such as a failure to meet
    ///   the threshold, an invalid `code_link`, or other possible issues within the `Shortener` module
    ///
    /// # Example Usage
    /// ```
    /// let env = Env::new(); // Initialize the environment.
    /// let code_link = "abc123".to_string(); // Example shortened link code.
    /// let threshold = 100; // Minimum required interactions.
    /// let duration = 3600; // Extend by 1 hour (3600 seconds).
    ///
    /// match extend_link_ttl(env, code_link, threshold, duration) {
    ///     Ok(_) => println!("TTL successfully extended."),
    ///     Err(e) => println!("Failed to extend TTL: {:?}", e),
    /// }
    /// ```
    ///
    /// # Note
    /// - Ensure `code_link` and other parameters are properly validated before calling this function.
    pub fn extend_link_ttl(
        env: Env,
        code_link: String,
        threshold: u32,
        duration: u32,
    ) -> Result<(), Error> {
        Shortener::extend_link_ttl(env, code_link, threshold, duration)
    }

    /// Set API Key V1 that is a client address from Sep0010 standard
    pub fn set_api_key_v1(env: Env, key: String, access: u32, ttl: u32) -> Result<(), Error> {
        ApiKey::set_api_key_v1(env, key, access, ttl)
    }

    /// Delete API key V1 that is a client address from Sep0010 standard
    pub fn delete_api_key_v1(env: Env, key: String) -> Result<(), Error> {
        ApiKey::delete_api_key_v1(env, key)
    }
    /// Upgrade smart contract
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        UpgradeableContract::upgrade(env, new_wasm_hash)
    }

    /// Retrieves the build version of the upgradeable contract.
    ///
    /// This function fetches the current build version of the contract.
    ///
    /// # Arguments
    ///
    /// * `env` - The environment in which the function is executed.
    ///   It typically provides access to context-specific details, such as blockchain state or
    ///   runtime configuration.
    ///
    /// # Returns
    ///
    /// A `String` representing the build version of the contract.
    ///
    /// # Example
    ///
    /// ```rust
    /// let env = Env::default();
    /// let build_version = version_build(env);
    /// println!("Contract Build Version: {}", build_version);
    /// ```
    ///
    pub fn version_build(env: Env) -> String {
        UpgradeableContract::version_build(env)
    }

    pub fn version() -> u32 {
        UpgradeableContract::version()
    }

    /// Extends the Time-To-Live (TTL) for specific persistent keys in the storage.
    ///
    /// This function checks if certain keys are present in the persistent storage
    /// associated with the environment. If a key exists, its TTL is extended
    /// to the maximum TTL value allowed by the storage system.
    ///
    /// # Parameters
    /// - `env`: The environment context containing the storage to operate on.
    ///
    /// # Behavior
    /// The function targets the following keys for TTL extension:
    /// - `BASE_URL`
    /// - `PUBLIC_KEY`
    /// - `WEB_AUT_CREDENTIALS`
    /// - `LAST_SHORT`
    /// - `LAST_TEMPORARY`
    /// - `LAST_DISPOSABLE`
    ///
    /// For each key, if it exists in the persistent storage, its TTL is updated
    /// to extend its lifetime by using the maximum allowable TTL value.
    ///
    /// The logic ensures TTLs for these keys are consistently maintained at their
    /// maximum possible duration based on the storage configuration.
    ///
    /// # Example
    /// ```
    /// // Example usage:
    /// extend_ttl(env);
    /// ```
    ///
    /// # Notes
    /// - Ensure that the provided `env` has a properly configured storage instance.
    /// - This function assumes the presence of constants (`BASE_URL`, `PUBLIC_KEY`, etc.).
    ///   These must be defined elsewhere in the code.
    pub fn extend_ttl(env: Env) {
        let max_ttl = env.storage().max_ttl();

        if env.storage().persistent().has(&BASE_URL) {
            env.storage()
                .persistent()
                .extend_ttl(&BASE_URL, max_ttl, max_ttl);
        }
        if env.storage().persistent().has(&PUBLIC_KEY) {
            env.storage()
                .persistent()
                .extend_ttl(&PUBLIC_KEY, max_ttl, max_ttl);
        }
        if env.storage().persistent().has(&WEB_AUT_CREDENTIALS) {
            env.storage()
                .persistent()
                .extend_ttl(&WEB_AUT_CREDENTIALS, max_ttl, max_ttl);
        }
        if env.storage().persistent().has(&LAST_SHORT) {
            env.storage()
                .persistent()
                .extend_ttl(&LAST_SHORT, max_ttl, max_ttl);
        }
        if env.storage().persistent().has(&LAST_TEMPORARY) {
            env.storage()
                .persistent()
                .extend_ttl(&LAST_TEMPORARY, max_ttl, max_ttl);
        }
        if env.storage().persistent().has(&LAST_DISPOSABLE) {
            env.storage()
                .persistent()
                .extend_ttl(&LAST_DISPOSABLE, max_ttl, max_ttl);
        }
        if env.storage().persistent().has(&APIKEY_V1) {
            env.storage()
                .persistent()
                .extend_ttl(&APIKEY_V1, max_ttl, max_ttl);
        }
    }

    const ADDRESS_BUFFER_SIZE: usize = 2048;

    // Derive a private key (scalar) from the contract address using SDK's sha256
    fn private_key_from_address(env: &Env) -> Bls12381Fr {
        let crypto = env.crypto();
        let address = env.current_contract_address();
        let address_raw: &mut [u8; Self::ADDRESS_BUFFER_SIZE] =
            &mut [0u8; Self::ADDRESS_BUFFER_SIZE];
        let address_str = address.to_string();
        let len = address_str.len() as usize;
        env.string_copy_to_slice(
            address_str.to_object(),
            Val::U32_ZERO,
            address_raw[..len].as_mut(),
        )
        .unwrap_optimized();
        // Hash address with SDK's sha256
        let address_bytes = <Bytes>::from_slice(&env, address_raw);

        let hash = crypto.sha256(&address_bytes);
        // Convert hash to scalar (Fr)
        Bls12381Fr::from_bytes(hash.to_bytes())
    }
}
