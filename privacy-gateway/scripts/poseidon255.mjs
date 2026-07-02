#!/usr/bin/env node
// =============================================================================
// poseidon255.mjs
//
// Pure-JS port of poseidon-bls12381-circom's Poseidon255 template, for
// computing hashes off-circuit (e.g. credential_commitment at KYC issuance
// time, policy_hash for the policy-binding commitment, or filling witness
// input templates for testing).
//
// The round constants and MDS matrix are parsed directly out of the vendored
// node_modules/poseidon-bls12381-circom/circuits/poseidon255_constants.circom
// at runtime -- they are never hand-transcribed, so this can't silently drift
// from what the circuit itself uses. If the package is upgraded, this keeps
// working unmodified as long as the constants file's shape is unchanged.
//
// Supports any arity from 1 to 16 inputs (t = nInputs + 1, matching
// N_P_ARRAY's length in poseidon255.circom). Constants/matrix are parsed
// once per arity and cached.
//
// Usage (CLI):
//   node scripts/poseidon255.mjs <in0> <in1> [...moreInputs]
//
// Usage (library):
//   import { poseidon255, poseidon255_2 } from './poseidon255.mjs'
// =============================================================================

import { readFileSync } from 'fs';
import { fileURLToPath, pathToFileURL } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONST_FILE = join(__dirname, '..', 'node_modules', 'poseidon-bls12381-circom', 'circuits', 'poseidon255_constants.circom');

// BLS12-381 scalar field modulus -- see the sage generation comment at the
// top of poseidon255_constants.circom.
const P = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

const N_F = 8; // full rounds, fixed regardless of arity
// N_P_ARRAY from poseidon255.circom -- partial rounds, indexed by nInputs - 1.
const N_P_ARRAY = [56, 56, 56, 56, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57];

const constSrc = readFileSync(CONST_FILE, 'utf8');

function extractBranch(fnName, t) {
  const fnStart = constSrc.indexOf(`function ${fnName}(`);
  if (fnStart === -1) throw new Error(`${fnName}() not found in ${CONST_FILE}`);
  const branchRe = new RegExp(`t == ${t}\\s*\\)\\s*\\{\\s*return\\s*(\\[[\\s\\S]*?\\]);`, 'm');
  const m = constSrc.slice(fnStart).match(branchRe);
  if (!m) throw new Error(`t == ${t} branch not found in ${fnName}()`);
  return m[1];
}

function parseHexArray(text) {
  const jsonish = text.replace(/0x[0-9a-fA-F]+/g, (h) => `"${h}"`);
  const toBig = (v) => (Array.isArray(v) ? v.map(toBig) : BigInt(v));
  return toBig(JSON.parse(jsonish));
}

function x5(v) {
  const v2 = (v * v) % P;
  const v4 = (v2 * v2) % P;
  return (v4 * v) % P;
}

const paramsCache = new Map();

function paramsFor(t) {
  if (paramsCache.has(t)) return paramsCache.get(t);
  const C = parseHexArray(extractBranch('CONSTANTS', t)); // flat, length t * (N_F + N_P)
  const M = parseHexArray(extractBranch('MATRIX', t));    // t x t
  const params = { C, M };
  paramsCache.set(t, params);
  return params;
}

function mix(state, M, t) {
  const out = new Array(t);
  for (let i = 0; i < t; i++) {
    let res = 0n;
    for (let j = 0; j < t; j++) res = (res + state[j] * M[i][j]) % P;
    out[i] = res;
  }
  return out;
}

/** Poseidon255 over an arbitrary number of inputs (1-16), matching the
 * circuit's Poseidon255(nInputs) template exactly. */
export function poseidon255(inputs) {
  const nInputs = inputs.length;
  if (nInputs < 1 || nInputs > N_P_ARRAY.length) {
    throw new Error(`poseidon255: nInputs must be 1-${N_P_ARRAY.length}, got ${nInputs}`);
  }
  const t = nInputs + 1;
  const N_P = N_P_ARRAY[nInputs - 1];
  const { C, M } = paramsFor(t);

  if (C.length !== t * (N_F + N_P)) {
    throw new Error(`Expected ${t * (N_F + N_P)} round constants for t=${t}, parsed ${C.length}`);
  }

  let state = [0n, ...inputs.map((v) => BigInt(v) % P)];

  for (let i = 0; i < N_F + N_P; i++) {
    const arked = state.map((v, j) => (v + C[i * t + j]) % P);
    const isFullRound = i < N_F / 2 || i >= N_F / 2 + N_P;
    const sboxed = isFullRound
      ? arked.map(x5)
      : [x5(arked[0]), ...arked.slice(1)];
    state = mix(sboxed, M, t);
  }
  return state[0];
}

/** Convenience wrapper for the arity-2 case used by every nullifier_hash and
 * verify_investor_jurisdiction's credential_commitment. */
export function poseidon255_2(in0, in1) {
  return poseidon255([in0, in1]);
}

// ─── CLI entrypoint ───────────────────────────────────────────────────────────
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const inputs = process.argv.slice(2);
  if (inputs.length < 1) {
    console.error('Usage: node poseidon255.mjs <in0> <in1> [...moreInputs]');
    process.exit(1);
  }
  console.log(poseidon255(inputs).toString());
}
