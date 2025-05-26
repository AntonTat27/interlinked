use soroban_sdk::{contracttype, symbol_short, String, Symbol};

/// BaseURL is a name of base url to form shortness link. Value is a String
pub(crate) const BASE_URL: Symbol = symbol_short!("BaseURL");

/// PublicKey is a web auth secp256r1 public key SEC-1 encoded. Value is a BytesN<65>
pub(crate) const PUBLIC_KEY: Symbol = symbol_short!("PublicKey");

/// Creds is a credentials for web auth. Value is a String of base64 encode structure
pub(crate) const WEB_AUT_CREDENTIALS: Symbol = symbol_short!("Creds");

/// LastLink is a name of last used name for shortness link. Value is a Symbol
pub(crate) const LAST_SHORT: Symbol = symbol_short!("LastLink");

/// Redirect is a type of action that should be done with the target link.
pub(crate) const REDIRECT_LINK: Symbol = symbol_short!("Redirect");

#[contracttype]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LinkInfo {
    pub(crate) dest: String,
    pub(crate) is_active: bool,
    pub(crate) link_type: Symbol,
}

#[contracttype]
pub enum StorageKey {
    /// DstLink is an id for destination mapping. Value is LinkInfo.
    DstLink(String),
}