#!/usr/bin/env node
// =============================================================================
// prepare_witness_input.mjs
//
// Transforms a human-authored witness input file into the exact shape the
// circuit's witness calculator needs, in four passes:
//
//   0. Validate that every independent field (i.e. not about to be
//      overwritten by an auto/derived field) is a decimal number -- e.g.
//      jurisdiction must be an ISO 3166-1 NUMERIC code like 784 (UAE), never
//      an alpha-3 text code like "CYP" or "RUS". Circuit signals are field
//      elements, not strings; a text code passed through unchecked would
//      otherwise fail many steps later with a cryptic "Cannot convert CYP
//      to a BigInt" deep inside the Poseidon hashing code, with no
//      indication of which field caused it.
//
//   1. Auto-generate fields (circuits.json circuits.<name>.auto_fields) --
//      e.g. context_id: "timestamp" generates a fresh value every run if
//      the field is absent from the input file (an explicit value in the
//      file is always left alone). This is for fields like context_id
//      where re-running with a stale value causes on-chain replay
//      rejection (NullifierAlreadyUsed) -- omit the field entirely from
//      inputs/<name>.json to get a new one on every run.
//
//   2. Expand fixed-size array fields (circuits.json circuits.<name>.array_fields)
//      -- e.g. policy_jurisdiction: "784,321" becomes the full 8-slot padded
//      array circom's fixed-size array signal actually requires. Runs BEFORE
//      derive, because policy_hash (a derived field) hashes the *expanded*
//      array, not the raw comma-string.
//
//   3. Derive computed fields (circuits.json circuits.<name>.derived_fields)
//      -- e.g. credential_commitment = Poseidon255(kyc_secret, jurisdiction),
//      or policy_hash = Poseidon255(...policy_jurisdiction) over an already-
//      expanded array field. These fields are never hand-authored: if
//      present in the input file they are overwritten, and they may be
//      omitted entirely. This is what eliminates "Assert Failed" errors from
//      editing an independent field (jurisdiction, context_id, kyc_secret)
//      without recomputing whatever hash depends on it -- the dependency
//      only needs to be declared once, in circuits.json, not remembered by
//      whoever edits the input file.
//
// Circuits with none of these metadata blocks just pass through unchanged.
//
// Usage:
//   node prepare_witness_input.mjs <circuitName> <inputPath> <outputPath> [contextLink] [freshKycSecret]
//
//   contextLink (optional) -- a gated-link shortcode/URL to use as
//   context_id, e.g. the value create_gated_link returned. Overrides any
//   context_id already in the input file AND skips auto_fields' random
//   generation entirely (it's checked for before Pass 1 runs). Encoded via
//   the same stringToFieldElement convention as everything else here --
//   whatever encodes context_id on the other end of a policy_hash
//   registration (e.g. the contract that called create_gated_link) MUST use
//   an identical encoding of an identical string, or the two will compute
//   different field elements and registry lookups will silently miss
//   (PolicyNotRegistered), not error about a mismatched encoding. If that
//   string is longer than 32 UTF-8 bytes (a full URL easily is), only the
//   first 32 bytes are kept -- pass just the shortcode, not the full URL,
//   unless you've confirmed the other side truncates identically.
//
//   freshKycSecret (optional) -- any non-empty value regenerates kyc_secret
//   as a fresh random 31-byte integer, overriding whatever is in the input
//   file. Needed because nullifier_hash = Poseidon255(kyc_secret,
//   context_id): re-proving against the SAME context_id (e.g. prove.ps1's
//   "prove" step reusing a cached code_link) with the SAME kyc_secret
//   produces the exact same nullifier_hash every time, which an on-chain
//   resolve_gated_link/verify call already submitted once will reject as a
//   replay (NullifierAlreadyUsed) on every subsequent attempt. This also
//   changes credential_commitment (= Poseidon255(kyc_secret, jurisdiction)),
//   so each such re-prove looks like a different credential/identity to
//   whatever (if anything) checks that value -- acceptable for iterating on
//   jurisdiction values against a test deployment, not a stand-in for a
//   real credential issuance flow.
// =============================================================================

import { readFileSync, writeFileSync } from 'fs';
import { randomBytes } from 'crypto';
import { loadCircuitMeta } from './circuit_meta.mjs';
import { poseidon255, poseidon255_2 } from './poseidon255.mjs';

const [, , circuitName, inputPath, outputPath, contextLink, freshKycSecret] = process.argv;
if (!circuitName || !inputPath || !outputPath) {
  console.error('Usage: node prepare_witness_input.mjs <circuitName> <inputPath> <outputPath> [contextLink] [freshKycSecret]');
  process.exit(1);
}

const meta = loadCircuitMeta(circuitName);
const input = JSON.parse(readFileSync(inputPath, 'utf8'));

// Same convention as link_id/context_id elsewhere: UTF-8 bytes, zero-padded
// to 32 bytes, interpreted as a big-endian integer.
function stringToFieldElement(str) {
  const buf = Buffer.alloc(32);
  Buffer.from(str, 'utf8').copy(buf);
  return BigInt('0x' + buf.toString('hex'));
}

// ─── Pass -1: context link override (highest priority -- explicit CLI value
// always wins over both a stale value already in the input file and
// auto_fields' random generation) ────────────────────────────────────────────
if (contextLink) {
  const autoFields = meta.auto_fields || {};
  if (!('context_id' in autoFields) && !(meta.public_signals || []).includes('context_id')) {
    throw new Error(`circuit "${circuitName}" has no context_id signal -- contextLink argument doesn't apply here`);
  }
  if (Buffer.byteLength(contextLink, 'utf8') > 32) {
    console.warn(`⚠ contextLink "${contextLink}" is over 32 UTF-8 bytes -- it will be truncated, which may not match what the link-creating contract used as context_id`);
  }
  input.context_id = stringToFieldElement(contextLink).toString();
}

// ─── Pass -1b: fresh kyc_secret override -- see header comment for why ──────
if (freshKycSecret) {
  input.kyc_secret = BigInt('0x' + randomBytes(31).toString('hex')).toString();
}

// ─── Pass 0: validate independent fields are decimal numbers ────────────────
// Skips fields that derived_fields will overwrite regardless of their
// current (possibly placeholder/stale) value -- nothing to gain from
// validating something about to be discarded.
const NUMERIC_RE = /^\d+$/;
const derivedFieldNames = new Set(Object.keys(meta.derived_fields || {}));
const arrayFieldNames = new Set(Object.keys(meta.array_fields || {}));

// Pipeline-only fields: read by prove.ps1/prove.sh (e.g. to call
// create_gated_link) but never signals on any circuit -- skipped here and
// stripped before writing witness_input.json below, since the witness
// calculator throws ("Too many values for input signal ...") on any
// top-level key that isn't a real circuit signal.
const PIPELINE_ONLY_FIELDS = new Set(['gated_link_url', 'gated_link_content_type']);

function checkNumeric(label, value) {
  if (!NUMERIC_RE.test(String(value))) {
    throw new Error(
      `"${label}" must be a decimal number (e.g. an ISO 3166-1 numeric ` +
      `jurisdiction code like 784 for UAE), not text -- got ${JSON.stringify(value)}. ` +
      `Alpha-3 codes like "CYP" or "RUS" are not valid field values; use the numeric code instead.`
    );
  }
}

for (const [field, value] of Object.entries(input)) {
  if (derivedFieldNames.has(field)) continue;
  if (PIPELINE_ONLY_FIELDS.has(field)) continue;
  if (arrayFieldNames.has(field)) {
    const tokens = Array.isArray(value) ? value : String(value).split(',').map(s => s.trim()).filter(s => s.length > 0);
    tokens.forEach((t, i) => checkNumeric(`${field}[${i}]`, t));
  } else {
    checkNumeric(field, value);
  }
}

// ─── Pass 1: auto-generate fields, only if not already present ──────────────
const autoFields = meta.auto_fields || {};
for (const [field, kind] of Object.entries(autoFields)) {
  if (field in input) continue; // explicit value wins -- never overridden
  if (kind !== 'timestamp') {
    throw new Error(`auto_fields.${field}: only "timestamp" is supported, got ${JSON.stringify(kind)}`);
  }
  const nonce = randomBytes(2).toString('hex');
  input[field] = stringToFieldElement(`auto-${Date.now()}-${nonce}`).toString();
}

// ─── Pass 2: expand fixed-size array fields ──────────────────────────────────
const arrayFields = meta.array_fields || {};
for (const [field, size] of Object.entries(arrayFields)) {
  if (!(field in input)) continue;

  const raw = input[field];
  const values = Array.isArray(raw)
    ? raw
    : String(raw).split(',').map(s => s.trim()).filter(s => s.length > 0);

  if (values.length === 0) {
    throw new Error(`"${field}" must have at least one value (got empty)`);
  }
  if (values.length > size) {
    throw new Error(
      `"${field}" has ${values.length} values but the circuit only has ${size} slots -- ` +
      `raise array_fields.${field} in circuits.json and recompile the circuit if you need more`
    );
  }

  const expanded = values.slice();
  while (expanded.length < size) {
    expanded.push(values[values.length - 1]); // pad by repeating the last real value
  }
  input[field] = expanded;
}

// ─── Pass 3: derive computed fields ──────────────────────────────────────────
const derivedFields = meta.derived_fields || {};
for (const [field, spec] of Object.entries(derivedFields)) {
  if (spec.poseidon2) {
    const [depA, depB] = spec.poseidon2;
    if (!(depA in input) || !(depB in input)) {
      throw new Error(`derived_fields.${field} needs "${depA}" and "${depB}" in the input file`);
    }
    input[field] = poseidon255_2(input[depA], input[depB]).toString();
  } else if (spec.poseidonArray) {
    const dep = spec.poseidonArray;
    if (!(dep in input)) {
      throw new Error(`derived_fields.${field} needs "${dep}" in the input file`);
    }
    const arr = input[dep];
    if (!Array.isArray(arr)) {
      throw new Error(`derived_fields.${field}: "${dep}" must already be an array (expand pass must run first) -- got ${JSON.stringify(arr)}`);
    }
    input[field] = poseidon255(arr).toString();
  } else {
    throw new Error(`derived_fields.${field}: only "poseidon2" or "poseidonArray" is supported, got ${JSON.stringify(spec)}`);
  }
}

// Pipeline-only fields never reach the witness calculator -- strip them
// regardless of whether prove.ps1/prove.sh already read them out of the
// original input file for their own (non-witness) purposes.
for (const field of PIPELINE_ONLY_FIELDS) {
  delete input[field];
}

writeFileSync(outputPath, JSON.stringify(input, null, 2));
