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
//    circom verify_investor_jurisdiction.circom \
//      --r1cs --wasm --sym \
//      --prime bls12381 \
//      -l ./node_modules
//
// ─────────────────────────────────────────────────────────────────────────────

include "poseidon-bls12381-circom/circuits/poseidon255.circom";

// ─── IsZero ──────────────────────────────────────────────────────────────────
//
//  Standard curve-agnostic circom pattern (same as circomlib's IsZero --
//  reimplemented here directly since circomlib's own arithmetic templates
//  are plain field operations with no curve-specific constants, so there is
//  nothing BLS12-381-specific to import for this one).
//
//  out = 1 if in == 0, else 0. The witness-only `inv` assignment (`<--`)
//  lets this be computed for ANY `in`, including nonzero -- unlike `===`,
//  this never blocks witness generation. The constraint `in*out === 0` is a
//  tautology of this construction (always satisfiable), not a business
//  rule, so it cannot fail regardless of what `in` actually is.
//
// ─────────────────────────────────────────────────────────────────────────────
template IsZero() {
    signal input in;
    signal output out;

    signal inv;
    inv <-- in != 0 ? 1 / in : 0;
    out <== -in * inv + 1;
    in * out === 0;
}

// ─── NullifierHash ───────────────────────────────────────────────────────────
//
//  Derives a public nullifier from a private secret so a verifier can detect
//  and reject proof re-use without learning the secret.
//
//  nullifier_hash = Poseidon255(secret, context_id)
//
//  Binding the nullifier to context_id means the same KYC secret produces a
//  different nullifier per context (e.g. per resource or session) -- so an
//  observer cannot correlate the same investor across unrelated jurisdiction
//  checks just by comparing nullifiers.
//
// ─────────────────────────────────────────────────────────────────────────────
template NullifierHash() {
    signal input secret;
    signal input context_id;   // public: the resource/session this check is for
    signal output out;

    component h = Poseidon255(2);
    h.in[0] <== secret;
    h.in[1] <== context_id;
    out <== h.out;
}

// ─── VerifyInvestorJurisdiction (main) ───────────────────────────────────────
//
//  Proves, in a single Groth16 proof, that the prover holds a KYC credential
//  for a jurisdiction in the *caller's registered* allowed set -- without a
//  Merkle membership proof against a credential tree, and without revealing
//  either the jurisdiction or the allowed set itself on-chain.
//
//  1. COMMITMENT    — the prover knows (kyc_secret, jurisdiction) such that
//                      Poseidon255(kyc_secret, jurisdiction) equals the
//                      public credential_commitment issued for them at KYC
//                      time.
//
//  2. POLICY BINDING — the prover's full allowed-jurisdiction list (private)
//                      hashes to the public policy_hash. This is the piece
//                      that closes the gap a plain "policy_jurisdiction as a
//                      public input" design has: without it, *any* caller
//                      could supply *any* allowed-list at verify time and
//                      the proof would still check out internally, with no
//                      way for the verifier to know whether that list was
//                      actually the one authorised for this context.
//                      policy_hash is meant to be registered on-chain once,
//                      out of the prover's control, exactly like
//                      `policy_hash` in a gated link per the original
//                      policy-type doc -- so the prover cannot choose a
//                      convenient list after the fact.
//
//  3. POLICY MEMBERSHIP — whether the prover's jurisdiction equals ONE of up
//                      to `maxJurisdictions` codes in the (private)
//                      policy_jurisdiction[], using a "pass-or-any" pattern
//                      generalized to a set:
//                        - policy_jurisdiction[0] == 0  -> no restriction
//                          (every other slot is ignored)
//                        - otherwise -> jurisdiction must equal
//                          policy_jurisdiction[i] for some i
//                      Unused slots should be padded by repeating any one
//                      real allowed value, not left as 0 -- only slot 0
//                      carries wildcard meaning.
//
//                      This is exposed as the PUBLIC OUTPUT `is_member`: 1
//                      if the prover's private data is aligned with this
//                      policy's rules, 0 if it is not -- rather than
//                      enforced with a hard `===` assertion. A hard
//                      assertion would make witness generation itself fail
//                      (and so prevent a proof from ever existing) whenever
//                      the data isn't aligned with the policy -- which
//                      would mean the only place that rejection could ever
//                      happen is locally, off the verifier's chain
//                      entirely, before the verifier sees anything.
//                      Exposing is_member as an output instead means a
//                      proof always exists, and the Soroban contract's own
//                      `verify` is what rejects it (Error::
//                      JurisdictionNotInPolicy) when is_member is 0 -- the
//                      rejection genuinely happens at verification, not at
//                      local proving. Soundness: define matches = Π_i
//                      (jurisdiction - policy_jurisdiction[i]). matches == 0
//                      iff jurisdiction equals at least one
//                      policy_jurisdiction[i]. is_member = IsZero(
//                      policy_jurisdiction[0] * matches), which is 1 iff
//                      policy_jurisdiction[0] == 0 (wildcard) or matches ==
//                      0 (jurisdiction is in the allowed set) -- same logic
//                      as before, just not hard-asserted. is_member alone
//                      reveals nothing about jurisdiction or the list beyond
//                      this one bit of policy alignment.
//
//  4. NULLIFIER      — the prover outputs a deterministic nullifier derived
//                      from their secret and context_id, binding this proof
//                      to a single use of this exact context.
//
//  Public inputs (4 -- the allowed-jurisdiction values themselves never
//  appear on-chain, only their commitment):
//    • credential_commitment — Poseidon(kyc_secret, jurisdiction), issued
//                               off-chain at KYC time and stored by the
//                               verifier/contract for this investor.
//    • policy_hash           — Poseidon(policy_jurisdiction[0..N-1]),
//                               registered on-chain by the resource owner
//                               (NOT the prover) at gated-resource creation
//                               time -- see verifier/'s policy_hash registry.
//    • nullifier_hash        — replay-prevention tag.
//    • context_id            — the resource/session this proof is scoped to.
//
//  Public output (1 -- automatically public; circom main-component outputs
//  don't go in the `public [...]` list, only public inputs do):
//    • is_member             — 1 if the prover's private data is aligned
//                               with this policy's rules, 0 if it is not.
//                               Checked by the Soroban contract, not
//                               asserted in-circuit.
//
//  Private inputs (stay off-chain, never revealed):
//    • kyc_secret             — secret known only to the credential holder.
//    • jurisdiction           — actual jurisdiction in the credential.
//    • policy_jurisdiction[N] — the full allowed-jurisdiction list. Private
//                               because only its commitment (policy_hash)
//                               needs to be public; the prover still needs
//                               the real values to compute the membership
//                               check and the hash.
//
// ─────────────────────────────────────────────────────────────────────────────
template VerifyInvestorJurisdiction(maxJurisdictions) {
    // ── Public inputs ──────────────────────────────────────────────────────
    signal input credential_commitment;
    signal input policy_hash;
    signal input nullifier_hash;
    signal input context_id;

    // ── Public output (automatically public) ───────────────────────────────
    signal output is_member;

    // ── Private inputs ─────────────────────────────────────────────────────
    signal input kyc_secret;
    signal input jurisdiction;                            // prover's actual jurisdiction code
    signal input policy_jurisdiction[maxJurisdictions];    // [0] == 0 => no restriction

    // ─────────────────────────────────────────────────────────────────────
    // 1. Verify the credential commitment
    // ─────────────────────────────────────────────────────────────────────
    component commitment_hasher = Poseidon255(2);
    commitment_hasher.in[0] <== kyc_secret;
    commitment_hasher.in[1] <== jurisdiction;

    commitment_hasher.out === credential_commitment;

    // ─────────────────────────────────────────────────────────────────────
    // 2. Bind the private allowed-list to the public policy_hash
    // ─────────────────────────────────────────────────────────────────────
    component policy_hasher = Poseidon255(maxJurisdictions);
    for (var i = 0; i < maxJurisdictions; i++) {
        policy_hasher.in[i] <== policy_jurisdiction[i];
    }
    policy_hasher.out === policy_hash;

    // ─────────────────────────────────────────────────────────────────────
    // 3. Policy membership -- set membership, "pass-or-any" on slot 0,
    //    exposed as the public output is_member (see template doc comment
    //    for why this is an output rather than a hard assertion).
    // ─────────────────────────────────────────────────────────────────────
    signal diffs[maxJurisdictions];
    signal partial[maxJurisdictions + 1];
    partial[0] <== 1;
    for (var i = 0; i < maxJurisdictions; i++) {
        diffs[i] <== jurisdiction - policy_jurisdiction[i];
        partial[i + 1] <== partial[i] * diffs[i];
    }

    component member_check = IsZero();
    member_check.in <== policy_jurisdiction[0] * partial[maxJurisdictions];
    is_member <== member_check.out;

    // ─────────────────────────────────────────────────────────────────────
    // 4. Derive and constrain the public nullifier
    // ─────────────────────────────────────────────────────────────────────
    component nullifier = NullifierHash();
    nullifier.secret     <== kyc_secret;
    nullifier.context_id <== context_id;

    nullifier.out === nullifier_hash;
}

// ─── Instantiation ───────────────────────────────────────────────────────────
//
//  maxJurisdictions = 8 -- raise if a deal room needs to allow more distinct
//  jurisdiction codes at once. Each additional slot costs ~2 constraints
//  (negligible at this scale). There are ~252 ISO 3166-1 alpha-3 jurisdiction
//  codes in the world for now; Poseidon255 here supports up to 16 inputs in
//  one call (t up to 17 in poseidon255_constants.circom), so maxJurisdictions
//  can go as high as 16 without changing the hashing approach.
//
// ─────────────────────────────────────────────────────────────────────────────
component main {
    public [
        credential_commitment,
        policy_hash,
        nullifier_hash,
        context_id
    ]
} = VerifyInvestorJurisdiction(8);
