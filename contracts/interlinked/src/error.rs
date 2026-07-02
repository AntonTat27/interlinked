use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    NotSupported = 0,
    NotInitiated = 1,
    AlreadyInitiated = 2,
    ClientDataJsonChallengeIncorrect = 3,
    Secp256r1PublicKeyParse = 4,
    Secp256r1SignatureParse = 5,
    Secp256r1VerifyFailed = 6,
    JsonParseError = 7,
    TooLong = 8,
    NotAuthorized = 9,
    DisposedOk = 10,
    DisposedErr = 11,
    VerifyingKeyNotSet = 12,
    PublicInputCountMismatch = 13,
    ProofVerificationFailed = 14,
    NullifierAlreadyUsed = 15,

    /// Caller is not the contract admin.
    Unauthorized = 16,

    /// public_inputs or ic was empty when at least one element was required.
    EmptyArgument = 17,

    /// A verifying key's nullifier_index/policy_hash_index/context_id_index
    /// metadata is inconsistent (e.g. an index out of range for the actual
    /// public_inputs length, or policy_hash_index set without
    /// context_id_index).
    InvalidVerifyingKeyMetadata = 18,

    /// This circuit's verifying key declares a policy_hash_index, but no
    /// policy_hash has been registered for the proof's context_id.
    PolicyNotRegistered = 19,

    /// The proof's policy_hash does not match the policy_hash registered
    /// for its context_id -- the prover used a different allowed-value list
    /// than the one actually authorised for this context.
    PolicyHashMismatch = 20,

    /// The proof is cryptographically valid (and policy_hash matches the
    /// registry), but its is_member output is 0 -- the prover's private
    /// data genuinely is not aligned with the registered policy's rules.
    /// Unlike the other errors here, this rejection happens after a real
    /// proof was successfully generated -- by design, see
    /// circuits/verify_investor_jurisdiction.circom.
    JurisdictionNotInPolicy = 21,
}
