#!/usr/bin/env node
// =============================================================================
// encode_for_soroban.mjs
//
// Converts snarkjs BLS12-381 Groth16 JSON artifacts into the byte layout
// expected by Soroban's native BLS12-381 host functions.
//
// Soroban BLS12-381 point encoding:
//   G1 (Bls12381G1Affine): 96 bytes  — uncompressed, big-endian
//                           [x: 48 bytes][y: 48 bytes]
//   G2 (Bls12381G2Affine): 192 bytes — uncompressed, big-endian
//                           [x_c1: 48][x_c0: 48][y_c1: 48][y_c0: 48]
//   Fr (Bls12381Fr):        32 bytes  — big-endian scalar
//
// snarkjs BLS12-381 output format:
//   G1 points: [x_decimal_str, y_decimal_str, "1"]
//   G2 points: [[x_c0, x_c1], [y_c0, y_c1], ["1","0"]]
//   Fr values: decimal strings
//
// Which public signal is the nullifier varies per circuit, so this script
// reads circuits.json (via circuit_meta.mjs) instead of hardcoding an index.
//
// Usage:
//   node encode_for_soroban.mjs <circuitName>
//   (reads target/<circuitName>/{verification_key,proof,public}.json,
//    writes target/<circuitName>/soroban_args.json)
// =============================================================================

import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { loadCircuitMeta } from './circuit_meta.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));

const [, , circuitName] = process.argv;
if (!circuitName) {
  console.error('Usage: node encode_for_soroban.mjs <circuitName>');
  process.exit(1);
}

const meta = loadCircuitMeta(circuitName);
const targetDir = join(__dirname, '..', 'target', circuitName);
const vkPath     = join(targetDir, 'verification_key.json');
const proofPath  = join(targetDir, 'proof.json');
const publicPath = join(targetDir, 'public.json');
const outPath    = join(targetDir, 'soroban_args.json');

const vk     = JSON.parse(readFileSync(vkPath,     'utf8'));
const proof  = JSON.parse(readFileSync(proofPath,  'utf8'));
const pub    = JSON.parse(readFileSync(publicPath, 'utf8'));

if (pub.length !== meta.public_signals.length) {
  throw new Error(
    `public.json has ${pub.length} signals but circuits.json declares ` +
    `${meta.public_signals.length} for "${circuitName}" -- update public_signals`
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Decimal string → 0-padded big-endian hex of `byteLen` bytes */
function decToHex(decStr, byteLen) {
  const n = BigInt(decStr);
  const hex = n.toString(16).padStart(byteLen * 2, '0');
  if (hex.length > byteLen * 2) {
    throw new Error(`Value ${decStr} overflows ${byteLen} bytes`);
  }
  return hex;
}

/** Encode an uncompressed G1 point: [x||y] = 96 bytes */
function encodeG1(point) {
  // point = [x_dec, y_dec, "1"]
  const x = decToHex(point[0], 48);
  const y = decToHex(point[1], 48);
  return x + y;   // 96 bytes = 192 hex chars
}

/**
 * Encode an uncompressed G2 point: [x_c1||x_c0||y_c1||y_c0] = 192 bytes
 *
 * snarkjs stores G2 as [[x_c0, x_c1], [y_c0, y_c1], ...]
 * Soroban BLS12-381 host expects the field extension elements in the
 * same Fp2 = (c1*u + c0) ordering used by the ZCash/IETF standard:
 *   bytes = x_c1 ++ x_c0 ++ y_c1 ++ y_c0
 */
function encodeG2(point) {
  const x_c0 = decToHex(point[0][0], 48);
  const x_c1 = decToHex(point[0][1], 48);
  const y_c0 = decToHex(point[1][0], 48);
  const y_c1 = decToHex(point[1][1], 48);
  return x_c1 + x_c0 + y_c1 + y_c0;  // 192 bytes = 384 hex chars
}

/** Encode a scalar Fr element: 32 bytes big-endian */
function encodeFr(decStr) {
  return decToHex(decStr, 32);
}

// ─── Verify curve matches ────────────────────────────────────────────────────
if (vk.curve !== 'bls12381') {
  throw new Error(`Expected curve bls12381, got ${vk.curve}. Did you compile with --prime bls12381?`);
}

// ─── Encode verifying key ────────────────────────────────────────────────────
const vk_encoded = {
  alpha_g1:  encodeG1(vk.vk_alpha_1),
  beta_g2:   encodeG2(vk.vk_beta_2),
  gamma_g2:  encodeG2(vk.vk_gamma_2),
  delta_g2:  encodeG2(vk.vk_delta_2),
  // ic[0] is the constant term; ic[1..] pair with public inputs
  ic: vk.IC.map(pt => encodeG1(pt)),
};

// ─── Encode proof ────────────────────────────────────────────────────────────
const proof_encoded = {
  a:  encodeG1(proof.pi_a),
  b:  encodeG2(proof.pi_b),
  c:  encodeG1(proof.pi_c),
};

// ─── Encode public inputs ────────────────────────────────────────────────────
// Order matches circuits.json public_signals for this circuit, which must
// match the circuit's component main { public [...] } declaration order.
const public_inputs_encoded = pub.map(s => encodeFr(s));
const nullifier_encoded = public_inputs_encoded[meta.nullifier_index];
const policy_hash_encoded = meta.policy_hash_index === null ? null : public_inputs_encoded[meta.policy_hash_index];
const context_id_encoded = meta.context_id_index === null ? null : public_inputs_encoded[meta.context_id_index];
const is_member_encoded = meta.is_member_index === null ? null : public_inputs_encoded[meta.is_member_index];

// ─── Stellar CLI argument format ─────────────────────────────────────────────
//
//  set_verifying_key(vk_id: String, alpha_g1: BytesN<96>, beta_g2: BytesN<192>,
//                    gamma_g2: BytesN<192>, delta_g2: BytesN<192>,
//                    ic: Vec<BytesN<96>>, nullifier_index: u32,
//                    policy_hash_index: Option<u32>, context_id_index: Option<u32>,
//                    is_member_index: Option<u32>)
//
//  verify(vk_id: String, proof_a: BytesN<96>, proof_b: BytesN<192>,
//         proof_c: BytesN<96>, public_inputs: Vec<BytesN<32>>)
//  -- no separate nullifier argument: the contract always reads it out of
//  public_inputs at nullifier_index, so it can never be a value disconnected
//  from what the proof actually commits to. A proof exists (and verify_argv
//  is generated) regardless of is_member's value -- private data that isn't
//  aligned with the policy produces a real, cryptographically valid proof
//  with is_member=0; the contract is what rejects it
//  (Error::JurisdictionNotInPolicy), not this pipeline. See the warning
//  below if that's the case.
//
//  register_policy_hash(context_id: BytesN<32>, policy_hash: BytesN<32>)
//  -- only meaningful (and only generated below) for circuits that declare
//  policy_hash_index/context_id_index. Must be called by whoever controls
//  the gated resource, NOT the prover -- this script can produce the argv,
//  but it's on the caller to invoke it with the admin/resource-owner key,
//  not the prover's.
//
const out = {
  circuit: circuitName,
  vk_id: meta.vk_id,
  curve: 'bls12381',
  public_signals: meta.public_signals,
  verifying_key: vk_encoded,
  proof: proof_encoded,
  public_inputs: public_inputs_encoded,
  nullifier: nullifier_encoded,
  policy_hash: policy_hash_encoded,
  context_id: context_id_encoded,
  is_member: is_member_encoded,

  // Flat argv arrays for scripted `stellar contract invoke` calls. Each
  // element is exactly one argv token -- prove.sh/prove.ps1 expand these
  // natively (bash "${arr[@]}", PowerShell @arr splat) so no shell ever has
  // to re-parse a combined string. --caller is deployment-specific (the
  // admin address), not circuit-specific, so it is NOT included here --
  // the calling script supplies it separately.
  set_verifying_key_argv: [
    '--vk_id', meta.vk_id,
    '--alpha_g1', vk_encoded.alpha_g1,
    '--beta_g2', vk_encoded.beta_g2,
    '--gamma_g2', vk_encoded.gamma_g2,
    '--delta_g2', vk_encoded.delta_g2,
    '--ic', JSON.stringify(vk_encoded.ic),
    '--nullifier_index', String(meta.nullifier_index),
    ...(meta.policy_hash_index === null ? [] : ['--policy_hash_index', String(meta.policy_hash_index)]),
    ...(meta.context_id_index === null ? [] : ['--context_id_index', String(meta.context_id_index)]),
    ...(meta.is_member_index === null ? [] : ['--is_member_index', String(meta.is_member_index)]),
  ],

  verify_argv: [
    '--vk_id', meta.vk_id,
    '--proof_a', proof_encoded.a,
    '--proof_b', proof_encoded.b,
    '--proof_c', proof_encoded.c,
    '--public_inputs', JSON.stringify(public_inputs_encoded),
  ],

  // Same proof/public_inputs tokens as verify_argv, minus --vk_id -- for
  // contracts whose resolve_gated_link(code_link, proof_a, proof_b, proof_c,
  // public_inputs) looks up vk_id server-side from the gated-link record
  // created at create_gated_link time, instead of taking it as a verify-time
  // argument. The caller prepends its own '--code_link', '<value>' pair.
  resolve_gated_link_argv: [
    '--proof_a', proof_encoded.a,
    '--proof_b', proof_encoded.b,
    '--proof_c', proof_encoded.c,
    '--public_inputs', JSON.stringify(public_inputs_encoded),
  ],

  // Only present for circuits that bind a policy commitment.
  register_policy_hash_argv: policy_hash_encoded === null ? null : [
    '--context_id', context_id_encoded,
    '--policy_hash', policy_hash_encoded,
  ],
};

writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log(`✓ encoded artifacts written to ${outPath}`);
console.log(`  circuit:  ${circuitName} (vk_id: ${meta.vk_id})`);
console.log(`  G1 size:  ${vk_encoded.alpha_g1.length / 2} bytes`);
console.log(`  G2 size:  ${vk_encoded.beta_g2.length / 2} bytes`);
console.log(`  VK ic[]:  ${vk_encoded.ic.length} points`);
if (meta.is_member_index !== null) {
  const isMemberValue = BigInt('0x' + is_member_encoded);
  if (isMemberValue === 0n) {
    console.log('  ⚠ is_member: 0 -- this is a real, valid proof, but the private data is NOT');
    console.log('    aligned with the registered policy. The contract is expected to reject it');
    console.log('    with Error::JurisdictionNotInPolicy, not this pipeline.');
  } else {
    console.log('  is_member: 1 (private data is aligned with the policy)');
  }
}
