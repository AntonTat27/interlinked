use soroban_sdk::{contracttype, symbol_short, Bytes, BytesN, Map, String, Symbol, Vec};

/// BaseURL is a name of base url to form a shortness link. Value is a String
pub(crate) const BASE_URL: Symbol = symbol_short!("BaseURL");

/// BaseURL is a name of base url to form a shortness link. Value is a String
pub(crate) const ADMIN: Symbol = symbol_short!("Admin");

/// PublicKey is a web auth secp256r1 public key SEC-1 encoded. Value is a BytesN<65>
pub(crate) const PUBLIC_KEY: Symbol = symbol_short!("PublicKey");

/// Creds is credentials for web auth. Value is a String of base64 encode structure
pub(crate) const WEB_AUT_CREDENTIALS: Symbol = symbol_short!("Creds");

/// LastLink is a name of last-used name for a shortness link. Value is a Symbol
pub(crate) const LAST_SHORT: Symbol = symbol_short!("LastLink");

/// LastLink is a name of last-used name for the temporary link. Value is a Symbol
pub(crate) const LAST_TEMPORARY: Symbol = symbol_short!("LastTemp");

/// LastLink is a name of last-used name for a disposable link. Value is a Symbol
pub(crate) const LAST_DISPOSABLE: Symbol = symbol_short!("LastDisp");

/// LastGated is a name of last-used name for a gated link. Value is a Symbol
pub(crate) const LAST_GATED: Symbol = symbol_short!("LastGate");

/// ApiKeyV1 is a first version to support API key on the base of SEP-0010.
/// Value is a map[api_key: String]ApiKeyV1
pub(crate) const APIKEY_V1: Symbol = symbol_short!("ApiKeyV1");

#[contracttype]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LinkInfo {
    pub(crate) dest: String,
    pub(crate) is_active: bool,
    pub(crate) content_type: String,
}

#[contracttype]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DisposableLinkInfo {
    pub(crate) dest: String,
    pub(crate) is_active: bool,
    pub(crate) content_type: String,
    pub(crate) signed_salt: BytesN<96>,
    pub(crate) failed_attempts: u32,
    pub(crate) failed_retries: u32,
    pub(crate) success_attempts: u32,
    pub(crate) success_retries: u32,
}

// ---------------------------------------------------------------------------
// Verifying key record
// ---------------------------------------------------------------------------

/// A Groth16 verifying key in raw BLS12-381 uncompressed-point byte form,
/// matching circuit/scripts/encode_for_soroban.mjs's set_verifying_key_args
/// exactly: alpha_g1 (96B), beta_g2/gamma_g2/delta_g2 (192B each), and ic
/// (one 96B G1 point per public input, plus the constant term ic[0]).
///
/// nullifier_index/policy_hash_index/context_id_index/is_member_index are
/// positions into a `verify` call's `public_inputs` array -- they let
/// `verify` pull out the nullifier (always) and, optionally, a policy_hash +
/// context_id + is_member to check whether the proof's private data is
/// aligned with the policy registered in the PolicyHash registry, WITHOUT
/// the contract needing to know anything about a specific circuit's signal
/// layout beyond these numbers, set once per circuit at `set_verifying_key`
/// time. The contract has no access to circuits.json's signal names --
/// these indices are how that name -> position mapping (computed
/// off-chain) reaches the chain.
///
/// is_member is a circuit OUTPUT, not an assertion: a circuit that can
/// produce a policy-violation result (rather than failing witness
/// generation outright) lets a real, valid proof exist either way, with
/// `verify` itself being what rejects data that isn't aligned with the
/// policy -- see circuits/verify_investor_jurisdiction.circom's template
/// doc comment for why this matters.
#[contracttype]
#[derive(Clone)]
pub struct VerifyingKey {
    pub alpha_g1: BytesN<96>,
    pub beta_g2: BytesN<192>,
    pub gamma_g2: BytesN<192>,
    pub delta_g2: BytesN<192>,
    pub ic: Vec<BytesN<96>>,
    pub nullifier_index: u32,
    pub policy_hash_index: Option<u32>,
    pub context_id_index: Option<u32>,
    pub is_member_index: Option<u32>,
}

#[contracttype]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AccessPolicy {
    /// hash of the public inputs the proof must commit to (jurisdiction, group id, etc.)
    pub(crate) policy_hash: BytesN<32>,
    /// Groth16 verifying key reference (or inline VK if small enough)
    pub(crate) vk_id: String, // e.g. "verify_investor_jurisdiction_v1", "verify_link_access_v1"
}

#[contracttype]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GatedLinkInfo {
    pub(crate) dest: String,
    pub(crate) is_active: bool,
    pub(crate) content_type: String,
    pub(crate) policy: AccessPolicy,
}

#[contracttype]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ApiKeyV1 {
    pub(crate) access: u32,
    pub(crate) ttl: u32, // in ms
    pub(crate) attributes: Option<Map<Symbol, Bytes>>,
}

#[contracttype]
pub enum StorageKey {
    /// DstLink is an id for destination mapping. Value is LinkInfo.
    DstLink(String),
    /// GatedLink is an id for ZK-gated destination mapping. Value is GatedLinkInfo.
    GatedLink(String),
    /// Nullifier marks a consumed proof for a given link. Value is bool.
    Nullifier(BytesN<32>),
    /// Groth16 verifying key, namespaced by vk_id (matches the string
    /// produced by circuit/scripts/encode_for_soroban.mjs, e.g.
    /// "verify_link_access_v1").
    VerifyingKey(String),
    /// Policy commitment registry: context_id -> Poseidon hash of the full
    /// allowed-value list for that context, registered by the resource
    /// owner (NOT the prover) at gated-resource creation time. This is what
    /// stops a caller from proving membership in a list of their own
    /// choosing -- the circuit binds policy_hash to a real list internally,
    /// and `verify` cross-checks that hash against this registry.
    PolicyHash(BytesN<32>),
}
