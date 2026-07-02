#!/usr/bin/env node
// =============================================================================
// circuit_meta.mjs
//
// Single source of truth for reading circuits.json. Used two ways:
//
//   1. As a library:  import { loadCircuitMeta } from './circuit_meta.mjs'
//   2. As a CLI, by prove.sh / prove.ps1 to pull a field into a shell var:
//        node scripts/circuit_meta.mjs <circuitName> [field]
//      With no [field], prints the resolved JSON object for the circuit
//      (pot_size merged in from the top-level pot_sizes table).
// =============================================================================

import { readFileSync } from 'fs';
import { fileURLToPath, pathToFileURL } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CIRCUITS_JSON = join(__dirname, '..', 'circuits.json');

export function loadCircuitMeta(circuitName) {
  const config = JSON.parse(readFileSync(CIRCUITS_JSON, 'utf8'));
  const entry = config.circuits[circuitName];
  if (!entry) {
    const known = Object.keys(config.circuits).join(', ');
    throw new Error(`Unknown circuit "${circuitName}". Defined in circuits.json: ${known}`);
  }
  const pot_size = config.pot_sizes[entry.prime];
  if (!pot_size) {
    throw new Error(`No pot_sizes entry for prime "${entry.prime}" in circuits.json`);
  }
  const nullifier_index = entry.public_signals.indexOf(entry.nullifier_signal);
  if (nullifier_index === -1) {
    throw new Error(`nullifier_signal "${entry.nullifier_signal}" not found in public_signals for "${circuitName}"`);
  }
  // policy_hash/context_id/is_member are optional, by fixed name convention --
  // only circuits that bind a policy commitment (like
  // verify_investor_jurisdiction) have them. -1 means "not present",
  // surfaced as null for circuits.json consumers (e.g. encode_for_soroban.mjs
  // maps that to Option::None on-chain). All three travel together: a
  // circuit that hashes/checks a policy needs all of them, or none.
  const policy_hash_index_raw = entry.public_signals.indexOf('policy_hash');
  const context_id_index_raw = entry.public_signals.indexOf('context_id');
  const is_member_index_raw = entry.public_signals.indexOf('is_member');
  const policy_hash_index = policy_hash_index_raw === -1 ? null : policy_hash_index_raw;
  const context_id_index = context_id_index_raw === -1 ? null : context_id_index_raw;
  const is_member_index = is_member_index_raw === -1 ? null : is_member_index_raw;
  const presentFlags = [policy_hash_index, context_id_index, is_member_index].map((v) => v === null);
  if (!presentFlags.every((v) => v === presentFlags[0])) {
    throw new Error(`"${circuitName}": policy_hash, context_id, and is_member must all be present in public_signals, or none`);
  }
  return {
    ...entry, pot_size, nullifier_index,
    policy_hash_index, context_id_index, is_member_index,
    name: circuitName,
  };
}

// ─── CLI entrypoint ───────────────────────────────────────────────────────────
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [, , circuitName, field] = process.argv;
  if (!circuitName) {
    console.error('Usage: node circuit_meta.mjs <circuitName> [field]');
    process.exit(1);
  }
  const meta = loadCircuitMeta(circuitName);
  if (field) {
    const value = meta[field];
    if (value === undefined) {
      console.error(`Unknown field "${field}". Available: ${Object.keys(meta).join(', ')}`);
      process.exit(1);
    }
    process.stdout.write(typeof value === 'string' ? value : JSON.stringify(value));
  } else {
    process.stdout.write(JSON.stringify(meta, null, 2));
  }
}
