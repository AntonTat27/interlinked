pragma circom 2.0.6;

// ─── Dependencies ────────────────────────────────────────────────────────────
//
//  circomlib Poseidon is BN254-native.  For BLS12-381 we use the drop-in
//  replacement: poseidon-bls12381-circom (npm: poseidon-bls12381-circom).
//  The template name is Poseidon255 and its interface matches circomlib's
//  Poseidon exactly, so the rest of the circuit is curve-agnostic.
//
//  Install:
//    npm install poseidon-bls12381-circom
//
//  Compile (note --prime bls12381):
//    circom verify_link_access.circom \
//      --r1cs --wasm --sym \
//      --prime bls12381 \
//      -l ./node_modules
//
// ─────────────────────────────────────────────────────────────────────────────

include "poseidon-bls12381-circom/circuits/poseidon255.circom";

// ─── MerkleProof ─────────────────────────────────────────────────────────────
//
//  Verifies a single Merkle inclusion proof using Poseidon255.
//  depth: number of levels (e.g. 20 → up to 2^20 members).
//
// ─────────────────────────────────────────────────────────────────────────────
template MerkleProof(depth) {
    // The leaf value whose membership we are proving
    signal input leaf;
    // Sibling hashes along the path to the root (one per level)
    signal input path_elements[depth];
    // Direction bits: 0 = current node is left child, 1 = right child
    signal input path_indices[depth];
    // The claimed Merkle root (public)
    signal output root;

    component hashers[depth];
    signal level_hashes[depth + 1];
    level_hashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // Each bit must be binary
        path_indices[i] * (path_indices[i] - 1) === 0;

        hashers[i] = Poseidon255(2);

        // If path_indices[i] == 0: hash(current, sibling)
        // If path_indices[i] == 1: hash(sibling, current)
        // Achieved with: left = current - idx*(current - sibling)
        //                right = sibling + idx*(current - sibling)
        var diff = level_hashes[i] - path_elements[i];
        hashers[i].in[0] <== level_hashes[i] - path_indices[i] * diff;
        hashers[i].in[1] <== path_elements[i] + path_indices[i] * diff;

        level_hashes[i + 1] <== hashers[i].out;
    }

    root <== level_hashes[depth];
}

// ─── NullifierHash ───────────────────────────────────────────────────────────
//
//  Derives a public nullifier from a private secret so the on-chain contract
//  can detect and reject proof re-use without learning the secret.
//
//  nullifier_hash = Poseidon255(secret, link_id)
//
//  Binding the nullifier to the link_id means the same KYC credential produces
//  a different nullifier for every distinct gated link — i.e. accessing two
//  properties does not let an observer correlate the investor's identity across
//  those two accesses.
//
// ─────────────────────────────────────────────────────────────────────────────
template NullifierHash() {
    signal input secret;
    signal input link_id;   // public: the shortcode / link identifier
    signal output out;

    component h = Poseidon255(2);
    h.in[0] <== secret;
    h.in[1] <== link_id;
    out <== h.out;
}

// ─── VerifyLinkAccess (main) ─────────────────────────────────────────────────
//
//  Proves three things simultaneously in a single Groth16 proof:
//
//  1. MEMBERSHIP  — the prover knows a leaf that is a member of the KYC
//                   Merkle tree whose root is committed on-chain.
//                   The leaf = Poseidon255(kyc_secret, wallet_address).
//
//  2. POLICY      — the leaf encodes the required jurisdiction and
//                   accreditation level at known bit positions, and these
//                   satisfy the access policy for this link.
//                   (Implemented here as range/equality constraints on
//                   policy_jurisdiction and policy_accredited.)
//
//  3. NULLIFIER   — the prover outputs a deterministic nullifier derived
//                   from their secret and the link_id, binding this proof
//                   to a single use of this exact link.
//
//  Public inputs (seen by the on-chain verifier):
//    • merkle_root          — current root of the KYC credential tree
//    • nullifier_hash       — replay-prevention tag stored on-chain
//    • link_id              — the gated link being accessed
//    • policy_jurisdiction  — required jurisdiction code (0 = any)
//    • policy_accredited    — required accreditation flag (0 = not required)
//
//  Private inputs (stay off-chain, never revealed):
//    • kyc_secret           — secret known only to the credential holder
//    • wallet_address       — prover's wallet (binds proof to identity)
//    • jurisdiction         — actual jurisdiction in the credential
//    • accredited           — actual accreditation flag in the credential
//    • path_elements[20]    — Merkle sibling hashes
//    • path_indices[20]     — Merkle path directions
//
// ─────────────────────────────────────────────────────────────────────────────
template VerifyLinkAccess(depth) {
    // ── Public inputs ──────────────────────────────────────────────────────
    signal input merkle_root;
    signal input nullifier_hash;
    signal input link_id;
    signal input policy_jurisdiction;   // 0 = no restriction
    signal input policy_accredited;     // 0 = not required, 1 = required

    // ── Private inputs ─────────────────────────────────────────────────────
    signal input kyc_secret;
    signal input wallet_address;
    signal input jurisdiction;          // prover's actual jurisdiction code
    signal input accredited;            // prover's actual accreditation flag
    signal input path_elements[depth];
    signal input path_indices[depth];

    // ─────────────────────────────────────────────────────────────────────
    // 1. Derive the leaf from the prover's secret and wallet
    // ─────────────────────────────────────────────────────────────────────
    component leaf_hasher = Poseidon255(4);
    leaf_hasher.in[0] <== kyc_secret;
    leaf_hasher.in[1] <== wallet_address;
    leaf_hasher.in[2] <== jurisdiction;
    leaf_hasher.in[3] <== accredited;

    // ─────────────────────────────────────────────────────────────────────
    // 2. Verify Merkle membership
    // ─────────────────────────────────────────────────────────────────────
    component merkle = MerkleProof(depth);
    merkle.leaf         <== leaf_hasher.out;
    merkle.path_elements <== path_elements;
    merkle.path_indices  <== path_indices;

    // Constrain the computed root to match the public root
    merkle.root === merkle_root;

    // ─────────────────────────────────────────────────────────────────────
    // 3. Policy enforcement
    //
    //    We use a "pass-or-any" pattern:
    //      if policy_X == 0 → no restriction (the difference is unconstrained)
    //      if policy_X != 0 → prover's value must equal the policy value
    //
    //    Implemented as: policy_X * (jurisdiction - policy_jurisdiction) == 0
    //    This is sound: if policy_jurisdiction == 0, the product is always 0.
    //    If policy_jurisdiction != 0, the constraint forces equality.
    // ─────────────────────────────────────────────────────────────────────
    signal juris_diff;
    juris_diff <== jurisdiction - policy_jurisdiction;
    policy_jurisdiction * juris_diff === 0;

    // accredited is a bit — enforce range
    accredited * (accredited - 1) === 0;
    policy_accredited * (policy_accredited - 1) === 0;

    // If accreditation is required, the prover must hold it
    // policy_accredited * (1 - accredited) === 0
    // i.e.: if policy_accredited==1 then accredited must be 1
    signal accred_fail;
    accred_fail <== 1 - accredited;
    policy_accredited * accred_fail === 0;

    // ─────────────────────────────────────────────────────────────────────
    // 4. Derive and constrain the public nullifier
    // ─────────────────────────────────────────────────────────────────────
    component nullifier = NullifierHash();
    nullifier.secret  <== kyc_secret;
    nullifier.link_id <== link_id;

    nullifier.out === nullifier_hash;
}

// ─── Instantiation ───────────────────────────────────────────────────────────
//
//  depth = 20 → supports up to 2^20 (~1 million) KYC credentials.
//  Adjust downward (e.g. 16) to reduce constraint count and proving time
//  if the KYC registry will be smaller.
//
// ─────────────────────────────────────────────────────────────────────────────
component main {
    public [
        merkle_root,
        nullifier_hash,
        link_id,
        policy_jurisdiction,
        policy_accredited
    ]
} = VerifyLinkAccess(20);
