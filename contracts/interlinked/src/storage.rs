use soroban_sdk::{contracttype, symbol_short, String, Symbol};

/// BaseURL is a name of base url to form shortness link. Value is a String
pub(crate) const BASE_URL: Symbol = symbol_short!("BaseURL");

/// LastLink is a name of last used name for shortness link. Value is a Symbol
pub(crate) const LAST_SHORT: Symbol = symbol_short!("LastLink");

#[contracttype]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LinkInfo {
    pub(crate) dest: String,
}

#[contracttype]
pub enum StorageKey {
    /// DstLink is an id for destination mapping. Value is LinkInfo.
    DstLink(String),
}