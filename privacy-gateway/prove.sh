#!/usr/bin/env bash
# =============================================================================
# Interlinked — policy circuit proof pipeline
# BLS12-381 Groth16 via Circom + snarkjs
#
# Supports any circuit listed in circuits.json. The Powers of Tau ceremony is
# shared across all circuits of the same prime (run once, reused by every
# circuit's groth16 setup) — adding a new policy circuit only re-runs
# compile + setup, never the ceremony.
#
# Prerequisites:
#   - circom >= 2.0.6          (cargo install circom)
#   - snarkjs >= 0.7            (npm install -g snarkjs)
#   - Node.js >= 18
#   - stellar-cli on PATH
#   - CONTRACT_ID and DEPLOYER_SECRET env vars set
#
# Usage:
#   ./prove.sh <circuit> [all|local|prove|verify|encode] [contextLink]
#     all      full pipeline (compile + setup + create_gated_link + prove +
#              verify + deploy VK + resolve_gated_link)  [default]
#     local    regenerate witness+proof from inputs/<circuit>.json and verify locally --
#              no network/contract calls at all. Use this to test
#              policy_jurisdiction/jurisdiction edits without touching the chain.
#     prove    create_gated_link + proof generation, then ALSO encode + call
#              the on-chain contract (skips compile + setup)
#     verify   re-verify the existing proof.json locally, without regenerating it
#     encode   re-encode existing proof/vk without re-proving
#
#     contextLink (optional, "local" step only) -- an arbitrary
#     shortcode/URL to use as context_id instead of inputs/<circuit>.json's
#     value or auto_fields' random one, for offline testing. See
#     prepare_witness_input.mjs's header comment for the encoding caveat
#     (32-byte UTF-8 limit). Example:
#       ./prove.sh verify_investor_jurisdiction local "abc123"
#
#     "all"/"prove" ignore this argument. "all" runs step_create_gated_link,
#     which calls create_gated_link itself (or reuses a cached code_link --
#     see FORCE_NEW_LINK below) and the resulting code_link becomes
#     context_id automatically. This requires gated_link_url/
#     gated_link_content_type in inputs/<circuit>.json. "prove" runs
#     step_reprove_existing_link instead, which has no create_gated_link
#     call in it at all -- it only re-proves against the code_link an
#     earlier "all" run already cached, erroring if none exists yet.
#
#     step_create_gated_link ("all" only) caches the returned code_link in
#     target/<circuit>/code_link.txt and reuses it on subsequent "all" runs,
#     so re-running "all" doesn't mint a new link every time. Set
#     FORCE_NEW_LINK=1 to delete the cache and create a genuinely new link
#     instead -- e.g. after changing gated_link_url/gated_link_content_type,
#     which the cache does NOT detect on its own. Has no effect on "prove".
#
#   Circuit names come from circuits.json. Adding a new policy type means:
#     1. drop the .circom file in circuits/
#     2. add its entry to circuits.json
#     3. add its witness input file to inputs/<circuit>.json
#     4. ./prove.sh <circuit> all
# =============================================================================

set -euo pipefail

CIRCUIT="${1:-}"
STEP="${2:-all}"
CONTEXT_LINK="${3:-}"
FORCE_NEW_LINK="${FORCE_NEW_LINK:-}"
# Set by step_reprove_existing_link/step_create_gated_link's reuse branch
# before calling step_prove -- see prepare_witness_input.mjs's header
# comment for why re-proving against an existing code_link needs this.
FRESH_KYC_SECRET="${FRESH_KYC_SECRET:-}"

# Fallback testnet deployer identity, used only when CONTRACT_ID/
# DEPLOYER_SECRET aren't provided via the environment. Committed to source
# control -- treat as a shared/throwaway testnet identity, never reuse it
# for anything holding real value.
DEFAULT_CONTRACT_ID="CCBGT2AD2GW5UCNFVP6WA46LK6CDDEUSFQBWF6EKEX5T63TA3L2RLPND"
DEFAULT_DEPLOYER_SECRET="SD4YG42JMHV76CSDGVVXN5QWT6NOKXQP75ESLYBKKVF7CN2O7VXEUYSE"

# Called by step_create_gated_link/step_deploy_vk (the only steps that talk
# to the contract) instead of hard-erroring when CONTRACT_ID/DEPLOYER_SECRET
# are absent -- falls back to the default testnet identity above.
require_contract_creds() {
  if [ -z "${CONTRACT_ID:-}" ]; then
    echo "⚠ CONTRACT_ID not set -- using default testnet contract: ${DEFAULT_CONTRACT_ID}" >&2
    CONTRACT_ID="${DEFAULT_CONTRACT_ID}"
  fi
  if [ -z "${DEPLOYER_SECRET:-}" ]; then
    echo "⚠ DEPLOYER_SECRET not set -- using default testnet deployer secret" >&2
    DEPLOYER_SECRET="${DEFAULT_DEPLOYER_SECRET}"
  fi
}

if [ -z "$CIRCUIT" ]; then
  echo "Usage: $0 <circuit> [all|local|prove|verify|encode]"
  echo "Known circuits:"
  node -e "Object.keys(require('./circuits.json').circuits).forEach(n => console.log('  ' + n))"
  exit 1
fi

PRIME=$(node ./scripts/circuit_meta.mjs "$CIRCUIT" prime)
POT_SIZE=$(node ./scripts/circuit_meta.mjs "$CIRCUIT" pot_size)
VK_ID=$(node ./scripts/circuit_meta.mjs "$CIRCUIT" vk_id)

DIR_OUT="./target/${CIRCUIT}"
POT_DIR="./target/pot"
POT_FINAL="${POT_DIR}/${PRIME}_${POT_SIZE}_final.ptau"
INPUT="./inputs/${CIRCUIT}.json"

# ─── Step: Install Poseidon BLS12-381 library ────────────────────────────────
step_deps() {
  echo "→ installing poseidon-bls12381-circom..."
  npm install poseidon-bls12381-circom
}

# ─── Step: Compile circuit ────────────────────────────────────────────────────
step_compile() {
  echo "→ compiling circuits/${CIRCUIT}.circom (prime: ${PRIME})..."
  mkdir -p "${DIR_OUT}"
  circom "circuits/${CIRCUIT}.circom" \
    --r1cs --wasm --sym \
    --prime "${PRIME}" \
    -l ./node_modules \
    --output "${DIR_OUT}"
  echo "   constraints: $(snarkjs r1cs info "${DIR_OUT}/${CIRCUIT}.r1cs" | grep 'n. of constraints')"
}

# ─── Step: Powers of Tau (shared per prime+size, run once) ──────────────────
step_ptau() {
  if [ -f "${POT_FINAL}" ]; then
    echo "→ reusing existing Powers of Tau: ${POT_FINAL}"
    return
  fi
  echo "→ powers of tau (${PRIME}, size ${POT_SIZE})..."
  mkdir -p "${POT_DIR}"
  snarkjs powersoftau new "${PRIME}" "${POT_SIZE}" \
    "${POT_DIR}/pot_0000.ptau" -v
  snarkjs powersoftau contribute \
    "${POT_DIR}/pot_0000.ptau" \
    "${POT_DIR}/pot_0001.ptau" \
    --name="interlinked-setup-1" -e="$(openssl rand -hex 32)"
  snarkjs powersoftau prepare phase2 \
    "${POT_DIR}/pot_0001.ptau" \
    "${POT_FINAL}" -v
  rm -f "${POT_DIR}/pot_0000.ptau" "${POT_DIR}/pot_0001.ptau"
}

# ─── Step: Groth16 trusted setup (circuit-specific) ──────────────────────────
step_setup() {
  echo "→ groth16 setup for ${CIRCUIT} (vk_id: ${VK_ID})..."
  snarkjs groth16 setup \
    "${DIR_OUT}/${CIRCUIT}.r1cs" \
    "${POT_FINAL}" \
    "${DIR_OUT}/${CIRCUIT}_0000.zkey"
  snarkjs zkey contribute \
    "${DIR_OUT}/${CIRCUIT}_0000.zkey" \
    "${DIR_OUT}/${CIRCUIT}_final.zkey" \
    --name="interlinked-circuit-1" -e="$(openssl rand -hex 32)"
  snarkjs zkey export verificationkey \
    "${DIR_OUT}/${CIRCUIT}_final.zkey" \
    "${DIR_OUT}/verification_key.json"
  echo "→ verification key written to ${DIR_OUT}/verification_key.json"
}

# ─── Step: Generate witness + proof ──────────────────────────────────────────
step_prove() {
  echo "→ generating witness..."
  # Derives circuits.json derived_fields (e.g. credential_commitment from
  # kyc_secret + jurisdiction) and expands array_fields (e.g.
  # policy_jurisdiction: "784,321" into the fixed-size padded array). No-op
  # for circuits with neither.
  node ./scripts/prepare_witness_input.mjs "${CIRCUIT}" "${INPUT}" "${DIR_OUT}/witness_input.json" "${CONTEXT_LINK}" "${FRESH_KYC_SECRET}"
  node "${DIR_OUT}/${CIRCUIT}_js/generate_witness.js" \
    "${DIR_OUT}/${CIRCUIT}_js/${CIRCUIT}.wasm" \
    "${DIR_OUT}/witness_input.json" \
    "${DIR_OUT}/witness.wtns"

  echo "→ generating groth16 proof (${PRIME})..."
  snarkjs groth16 prove \
    "${DIR_OUT}/${CIRCUIT}_final.zkey" \
    "${DIR_OUT}/witness.wtns" \
    "${DIR_OUT}/proof.json" \
    "${DIR_OUT}/public.json"
}

# ─── Step: Local verification ────────────────────────────────────────────────
step_verify() {
  echo "→ verifying locally with snarkjs..."
  snarkjs groth16 verify \
    "${DIR_OUT}/verification_key.json" \
    "${DIR_OUT}/public.json" \
    "${DIR_OUT}/proof.json"
  echo "✓ local verification passed"
}

# ─── Step: Encode for Soroban ────────────────────────────────────────────────
#
#  Soroban BLS12-381 host functions expect points as uncompressed big-endian
#  bytes, G1 = 96 bytes (two 48-byte coordinates), G2 = 192 bytes (four
#  48-byte coordinates), Fr = 32 bytes.
#
#  encode_for_soroban.mjs reads circuits.json to find which public signal is
#  the nullifier, so it works unmodified for any circuit listed there.
#
step_encode() {
  echo "→ encoding proof + VK for Soroban BLS12-381 layout..."
  node ./scripts/encode_for_soroban.mjs "${CIRCUIT}"
}

# ─── Step: Upload VK to contract ─────────────────────────────────────────────
#
#  set_verifying_key_argv (from encode_for_soroban.mjs) is a flat JSON array
#  of argv tokens. Reading it one-element-per-line into a bash array and
#  expanding it with "${argv[@]}" passes each token as its own argument --
#  this avoids ever re-parsing a combined string, which is what broke here
#  previously (JSON.stringify of the whole args *object* was glued into one
#  unquoted blob and rejected by the CLI as a single unexpected argument).
#
step_deploy_vk() {
  echo "→ uploading verifying key to contract (vk_id: ${VK_ID})..."
  require_contract_creds
  # No --caller argument -- the contract authenticates via
  # read_admin(env).require_auth() internally, so DEPLOYER_SECRET's
  # corresponding address must itself be the registered admin.
  local argv=()
  while IFS= read -r line; do argv+=("$line"); done < <(node -e "
    const a = require('./${DIR_OUT}/soroban_args.json');
    a.set_verifying_key_argv.forEach(x => process.stdout.write(x + '\n'));
  ")
  stellar contract invoke \
    --id "${CONTRACT_ID}" \
    --source "${DEPLOYER_SECRET}" \
    --network testnet \
    -- set_verifying_key "${argv[@]}"
  echo "✓ verifying key uploaded"
}

# ─── Step: Re-prove against an EXISTING gated link only (used by "prove") ────
#
#  No create_gated_link call exists anywhere in this function's body -- not
#  just a guarded one. Calling this instead of step_create_gated_link makes
#  "prove" structurally incapable of minting a new link, regardless of
#  FORCE_NEW_LINK or cache state. It re-proves on the basis of whatever
#  jurisdiction/policy_jurisdiction currently is in inputs/<circuit>.json,
#  using the code_link cached by an earlier "all" run.
#
step_reprove_existing_link() {
  local code_link_cache_file="${DIR_OUT}/code_link.txt"
  if [ ! -f "$code_link_cache_file" ]; then
    echo "no gated link exists yet for ${CIRCUIT} (${code_link_cache_file} not found) -- run './prove.sh ${CIRCUIT} all' once first to create one, then use the prove step for subsequent runs" >&2
    exit 1
  fi
  CODE_LINK=$(cat "$code_link_cache_file")
  echo "→ reusing cached gated link: ${CODE_LINK}"
  # gated_link_url/content_type/policy_hash were fixed when the link was
  # created; jurisdiction/policy_jurisdiction are free to have changed
  # since -- that's the whole point of this step. FRESH_KYC_SECRET avoids
  # NullifierAlreadyUsed: same context_id + same kyc_secret would otherwise
  # produce the exact nullifier_hash already consumed by an earlier
  # successful on-chain call against this same code_link.
  CONTEXT_LINK="${CODE_LINK}"
  FRESH_KYC_SECRET=1
  step_prove
}

# ─── Step: Create gated link (replaces register_policy_hash on this contract) ─
#
#  Used only by "all" -- creates a gated link if none is cached yet (or
#  FORCE_NEW_LINK was set), or reuses the cached one otherwise, then proves
#  against whichever code_link results.
#
#  Must be called with the resource-owner/admin identity, never the
#  prover's -- a prover who could also set this registry entry would just
#  register whatever policy_hash matches the list they feel like proving,
#  defeating the whole point of the binding.
#
#  policy_hash only depends on policy_jurisdiction, never on context_id, so
#  it's safe to derive it via a pre-pass (no proof generated yet) before we
#  know what code_link create_gated_link will return -- this avoids
#  generating a real (expensive) proof twice: once to learn policy_hash,
#  once more with the real context_id.
#
step_create_gated_link() {
  require_contract_creds

  local code_link_cache_file="${DIR_OUT}/code_link.txt"
  if [ -n "$FORCE_NEW_LINK" ] && [ -f "$code_link_cache_file" ]; then
    rm -f "$code_link_cache_file"
  fi
  if [ -f "$code_link_cache_file" ]; then
    CODE_LINK=$(cat "$code_link_cache_file")
    echo "→ reusing cached gated link: ${CODE_LINK} (delete ${code_link_cache_file} or set FORCE_NEW_LINK=1 for a new one)"
    # FRESH_KYC_SECRET avoids NullifierAlreadyUsed -- see
    # step_reprove_existing_link's comment for why.
    CONTEXT_LINK="${CODE_LINK}"
    FRESH_KYC_SECRET=1
    step_prove
    return
  fi

  echo "→ deriving policy_hash (pre-pass, no proof generated yet)..."
  node ./scripts/prepare_witness_input.mjs "${CIRCUIT}" "${INPUT}" "${DIR_OUT}/witness_input_prepass.json"
  local policy_hash_dec
  policy_hash_dec=$(node -e "
    const w = require('./${DIR_OUT}/witness_input_prepass.json');
    if (!w.policy_hash) { console.error('circuit ${CIRCUIT} has no policy_hash field -- create_gated_link needs one (see circuits.json derived_fields)'); process.exit(1); }
    process.stdout.write(w.policy_hash);
  ")
  # Same decimal-string -> 32-byte big-endian hex conversion as
  # encode_for_soroban.mjs's decToHex -- policy_hash here is a BytesN<32>
  # argument, same as everywhere else in this pipeline.
  local policy_hash_hex
  policy_hash_hex=$(node -e "process.stdout.write(BigInt(process.argv[1]).toString(16).padStart(64, '0'))" "${policy_hash_dec}")

  local gated_link_url gated_link_content_type
  gated_link_url=$(node -e "const i = require('./${INPUT}'); process.stdout.write(i.gated_link_url || '');")
  gated_link_content_type=$(node -e "const i = require('./${INPUT}'); process.stdout.write(i.gated_link_content_type || '');")
  if [ -z "$gated_link_url" ] || [ -z "$gated_link_content_type" ]; then
    echo "inputs/${CIRCUIT}.json needs gated_link_url and gated_link_content_type to call create_gated_link" >&2
    exit 1
  fi

  echo "→ calling create_gated_link (vk_id: ${VK_ID})..."
  # NOTE: assumes `stellar contract invoke` prints a String return value as
  # its last stdout line, quoted -- verify this against actual CLI output
  # the first time this runs; adjust the strip/parse below if the format
  # differs.
  local invoke_output
  invoke_output=$(stellar contract invoke \
    --id "${CONTRACT_ID}" \
    --source "${DEPLOYER_SECRET}" \
    --network testnet \
    -- create_gated_link \
    --url "${gated_link_url}" \
    --content_type "${gated_link_content_type}" \
    --policy_hash "${policy_hash_hex}" \
    --vk_id "${VK_ID}")
  local created_url
  created_url=$(echo "$invoke_output" | tail -n 1 | sed 's/^"//; s/"$//')
  # create_gated_link returns the full URL (e.g. "https://base.url/!e") --
  # resolve_gated_link's code_link parameter, and context_id, need just the
  # shortcode suffix after the last "/", not the whole URL.
  CODE_LINK="${created_url##*/}"
  echo "$CODE_LINK" > "$code_link_cache_file"
  echo "✓ gated link created: ${created_url} (code_link: ${CODE_LINK}, cached at ${code_link_cache_file})"

  # Now run the REAL proving step with context_id = code_link, so the proof
  # actually submitted to resolve_gated_link is scoped to this link -- not
  # the throwaway/random context_id the pre-pass above used.
  CONTEXT_LINK="${CODE_LINK}"
  step_prove
}

# ─── Step: On-chain proof verification smoke test ────────────────────────────
step_onchain_verify() {
  : "${CODE_LINK:?no code_link available -- run step_create_gated_link first (resolve_gated_link needs it)}"
  echo "→ calling resolve_gated_link on Testnet (code_link: ${CODE_LINK})..."
  local argv=()
  while IFS= read -r line; do argv+=("$line"); done < <(node -e "
    const a = require('./${DIR_OUT}/soroban_args.json');
    a.resolve_gated_link_argv.forEach(x => process.stdout.write(x + '\n'));
  ")
  stellar contract invoke \
    --id "${CONTRACT_ID}" \
    --source "${DEPLOYER_SECRET}" \
    --network testnet \
    -- resolve_gated_link --code_link "${CODE_LINK}" "${argv[@]}"
  echo "✓ resolve_gated_link passed"
}

# ─── Entrypoint ──────────────────────────────────────────────────────────────
case "${STEP}" in
  all)
    # "all" rebuilds everything from scratch (compile/ptau/setup), so any
    # code_link.txt left over from a previous run is stale by definition
    # (it may have been registered against an old circuit version's
    # verifying key) -- always start fresh here, unlike step_create_gated_link's
    # own cache check (which "all" effectively bypasses via this deletion,
    # but is still safe to leave in place for clarity/defense in depth).
    rm -f "${DIR_OUT}/code_link.txt"

    step_deps
    step_compile
    step_ptau
    step_setup
    step_create_gated_link
    step_verify
    step_encode
    step_deploy_vk
    step_onchain_verify
    ;;
  local)
    step_prove
    step_verify
    ;;
  prove)
    step_reprove_existing_link
    step_verify
    step_encode
    step_deploy_vk
    step_onchain_verify
    ;;
  verify)
    step_verify
    ;;
  encode)
    step_encode
    ;;
  *)
    echo "Usage: $0 <circuit> [all|local|prove|verify|encode]"
    exit 1
    ;;
esac
