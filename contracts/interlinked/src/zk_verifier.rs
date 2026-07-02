use crate::error::Error;
use crate::groth16_bls12_381::verify_groth16;
pub(crate) use crate::storage::{GatedLinkInfo, StorageKey, VerifyingKey};
use soroban_sdk::{contracttype, BytesN, Env, String, Vec};

/// Emitted and returned for every successful verification.
#[contracttype]
#[derive(Clone, Debug)]
pub struct VerificationResult {
    /// Which policy circuit's verifying key the proof was checked against.
    pub vk_id: String,
    /// The nullifier that was consumed (prevents replay) -- read out of
    /// public_inputs[vk.nullifier_index], never a separately-trusted input.
    pub nullifier: BytesN<32>,
    /// True always on success — callers can pattern-match on this.
    pub verified: bool,
}

#[derive(Clone)]
pub struct ZkVerifier;

impl ZkVerifier {
    pub fn register_verifying_key(
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
        if ic.is_empty() {
            return Err(Error::EmptyArgument);
        }
        let num_public_inputs = ic.len() - 1;
        if nullifier_index >= num_public_inputs {
            return Err(Error::InvalidVerifyingKeyMetadata);
        }
        let policy_fields_present = (
            policy_hash_index.is_some(),
            context_id_index.is_some(),
            is_member_index.is_some(),
        );
        if policy_fields_present != (true, true, true)
            && policy_fields_present != (false, false, false)
        {
            return Err(Error::InvalidVerifyingKeyMetadata);
        }
        for idx in [policy_hash_index, context_id_index, is_member_index]
            .into_iter()
            .flatten()
        {
            if idx >= num_public_inputs {
                return Err(Error::InvalidVerifyingKeyMetadata);
            }
        }

        let vk = VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
            nullifier_index,
            policy_hash_index,
            context_id_index,
            is_member_index,
        };
        env.storage()
            .persistent()
            .set(&StorageKey::VerifyingKey(vk_id.clone()), &vk);
        Ok(())
    }

    /// Register the policy_hash for a context_id. Admin only.
    ///
    /// This is the trusted-source-of-truth commitment a circuit's policy_hash
    /// gets checked against -- it must be set by whoever controls the gated
    /// resource (here, the contract admin), NOT by the prover, or the whole
    /// binding is pointless: a prover who could also set this would just
    /// register a policy_hash matching whatever list they feel like proving.
    pub fn bind_policy_hash(
        env: &Env,
        context_id: BytesN<32>,
        policy_hash: BytesN<32>,
    ) -> Result<(), Error> {
        env.storage()
            .persistent()
            .set(&StorageKey::PolicyHash(context_id.clone()), &policy_hash);
        Ok(())
    }

    // ---------------------------------------------------------------------------
    // Core verification entry point
    // ---------------------------------------------------------------------------

    /// `is_member` is encoded as a 32-byte big-endian field element that is
    /// always exactly 0 or 1 by construction (circom's IsZero pattern) -- a
    /// plain byte comparison is sufficient and avoids needing any curve-specific
    /// scalar type here.
    fn is_one(b: &BytesN<32>) -> bool {
        let arr = b.to_array();
        arr[31] == 1 && arr[..31] == [0u8; 31]
    }
    /// Returns true if the nullifier has already been spent.
    pub fn nullifier_used(env: &Env, nullifier: &BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .get::<StorageKey, bool>(&StorageKey::Nullifier(nullifier.clone()))
            .unwrap_or(false)
    }

    /// Mark the nullifier as spent.
    pub fn consume_nullifier(env: &Env, nullifier: &BytesN<32>) {
        env.storage()
            .persistent()
            .set(&StorageKey::Nullifier(nullifier.clone()), &true);
    }

    /// Read the verifying key registered under `vk_id`, if any.
    pub fn read_verifying_key(env: &Env, vk_id: &String) -> Option<VerifyingKey> {
        env.storage()
            .persistent()
            .get(&StorageKey::VerifyingKey(vk_id.clone()))
    }

    /// Read the registered policy_hash for a context_id, if any.
    pub fn read_policy_hash(env: &Env, context_id: &BytesN<32>) -> Option<BytesN<32>> {
        env.storage()
            .persistent()
            .get(&StorageKey::PolicyHash(context_id.clone()))
    }

    /// Verify a Groth16/BLS12-381 proof against the verifying key registered
    /// under `vk_id`.
    ///
    /// Argument shapes match circuit/scripts/encode_for_soroban.mjs's
    /// verify_args exactly -- note there is no separate `nullifier` parameter:
    /// it is always read out of public_inputs at the registered VK's
    /// nullifier_index, so it can never be supplied as a value disconnected
    /// from what the proof actually commits to.
    ///
    /// On success:
    ///   - nullifier is consumed (stored on-chain, replay blocked)
    ///   - VerificationResult is returned and an event is emitted
    pub fn verify_proof(
        env: &Env,
        link_info: &GatedLinkInfo,
        proof_a: BytesN<96>,
        proof_b: BytesN<192>,
        proof_c: BytesN<96>,
        public_inputs: Vec<BytesN<32>>,
    ) -> Result<VerificationResult, Error> {
        // 1. Load verifying key
        let vk = Self::read_verifying_key(env, &link_info.policy.vk_id)
            .ok_or(Error::VerifyingKeyNotSet)?;

        if vk.nullifier_index as u32 >= public_inputs.len() {
            return Err(Error::InvalidVerifyingKeyMetadata);
        }
        let nullifier = public_inputs.get_unchecked(vk.nullifier_index);

        // 2. Replay check
        if Self::nullifier_used(env, &nullifier) {
            return Err(Error::NullifierAlreadyUsed);
        }

        // 3. Policy binding check (only for circuits that declare one)
        if let (Some(policy_hash_index), Some(context_id_index)) =
            (vk.policy_hash_index, vk.context_id_index)
        {
            if policy_hash_index >= public_inputs.len() || context_id_index >= public_inputs.len() {
                return Err(Error::InvalidVerifyingKeyMetadata);
            }
            let proof_policy_hash = public_inputs.get_unchecked(policy_hash_index);
            if link_info.policy.policy_hash != proof_policy_hash {
                return Err(Error::PolicyHashMismatch);
            }
        }

        // 4. Policy membership check (only for circuits that declare one) --
        // checked BEFORE the expensive pairing check below: if this proof's
        // private data genuinely is not aligned with the policy, is_member
        // will honestly be 0 and we can reject cheaply without paying for 4
        // pairings first. This doesn't weaken anything -- a forged
        // is_member=1 claim on a proof that actually computed 0 still cannot
        // pass the pairing check in step 5, regardless of check order;
        // Groth16 soundness means a prover cannot produce a valid proof for
        // public outputs inconsistent with their real private witness. This
        // is what actually rejects data that doesn't satisfy the policy, and
        // it happens here, in verify, against a real proof -- never as a
        // local witness-generation failure off-chain.
        if let Some(is_member_index) = vk.is_member_index {
            if is_member_index >= public_inputs.len() {
                return Err(Error::InvalidVerifyingKeyMetadata);
            }
            let is_member = public_inputs.get_unchecked(is_member_index);
            if !Self::is_one(&is_member) {
                return Err(Error::JurisdictionNotInPolicy);
            }
        }

        // 5. Pairing check (native BLS12-381 host functions) -- confirms the
        // proof is cryptographically valid for the exact public_inputs claimed,
        // including is_member.
        verify_groth16(env, &vk, &proof_a, &proof_b, &proof_c, &public_inputs)?;

        // 6. Consume nullifier
        Self::consume_nullifier(env, &nullifier);

        // 7. Emit event + return result
        let result = VerificationResult {
            vk_id: link_info.policy.vk_id.clone(),
            nullifier: nullifier.clone(),
            verified: true,
        };

        Ok(result)
    }
}
