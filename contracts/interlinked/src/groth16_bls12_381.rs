/// groth16_bls12_381.rs
///
/// Groth16 verification using Soroban's native BLS12-381 host functions
/// (env.crypto().bls12_381()) -- no ark-* pairing crate needed, unlike
/// temp/zk_verifier.rs's BN254/ark-groth16 approach. This mirrors exactly
/// what circuit/scripts/encode_for_soroban.mjs encodes off-chain.
///
/// Groth16 verification equation:
///   e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
/// where vk_x = ic[0] + sum_i(public_input[i] * ic[i + 1]).
///
/// The host only exposes pairing_check (product-of-pairings-equals-identity),
/// not raw pairing evaluation, so the equation is folded into a single
/// multi-pairing check by negating three of the four G1 inputs:
///   e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) == 1
/// This is sound because e(-P, Q) = e(P, Q)^-1 for any pairing.
use soroban_sdk::{
    crypto::bls12_381::{Bls12381Fr, Bls12381G1Affine, Bls12381G2Affine},
    BytesN, Env, Vec, U256,
};

use crate::error::Error;
use crate::storage::VerifyingKey;

/// Verifies a Groth16/BLS12-381 proof against `vk`.
///
/// `public_inputs.len()` must equal `vk.ic.len() - 1` -- `ic[0]` is the
/// constant term, `ic[1..]` pair positionally with `public_inputs`.
pub fn verify_groth16(
    env: &Env,
    vk: &VerifyingKey,
    proof_a: &BytesN<96>,
    proof_b: &BytesN<192>,
    proof_c: &BytesN<96>,
    public_inputs: &Vec<BytesN<32>>,
) -> Result<(), Error> {
    if vk.ic.is_empty() {
        return Err(Error::EmptyArgument);
    }
    if vk.ic.len() != public_inputs.len() + 1 {
        return Err(Error::PublicInputCountMismatch);
    }

    let bls = env.crypto().bls12_381();

    // ── vk_x = ic[0] + sum_i(public_input[i] * ic[i + 1]) via a single MSM ──
    let mut ic_points: Vec<Bls12381G1Affine> = Vec::new(env);
    let mut scalars: Vec<Bls12381Fr> = Vec::new(env);

    ic_points.push_back(Bls12381G1Affine::from_bytes(vk.ic.get_unchecked(0)));
    scalars.push_back(Bls12381Fr::from_u256(U256::from_u32(env, 1)));

    for i in 0..public_inputs.len() {
        ic_points.push_back(Bls12381G1Affine::from_bytes(vk.ic.get_unchecked(i + 1)));
        scalars.push_back(Bls12381Fr::from_bytes(public_inputs.get_unchecked(i)));
    }

    let vk_x = bls.g1_msm(ic_points, scalars);

    // ── Fold the verification equation into one multi-pairing check ──────────
    let a = Bls12381G1Affine::from_bytes(proof_a.clone());
    let b = Bls12381G2Affine::from_bytes(proof_b.clone());
    let c = Bls12381G1Affine::from_bytes(proof_c.clone());
    let alpha = Bls12381G1Affine::from_bytes(vk.alpha_g1.clone());
    let beta = Bls12381G2Affine::from_bytes(vk.beta_g2.clone());
    let gamma = Bls12381G2Affine::from_bytes(vk.gamma_g2.clone());
    let delta = Bls12381G2Affine::from_bytes(vk.delta_g2.clone());

    let mut vp1: Vec<Bls12381G1Affine> = Vec::new(env);
    vp1.push_back(a);
    vp1.push_back(-alpha);
    vp1.push_back(-vk_x);
    vp1.push_back(-c);

    let mut vp2: Vec<Bls12381G2Affine> = Vec::new(env);
    vp2.push_back(b);
    vp2.push_back(beta);
    vp2.push_back(gamma);
    vp2.push_back(delta);

    if bls.pairing_check(vp1, vp2) {
        Ok(())
    } else {
        Err(Error::ProofVerificationFailed)
    }
}
