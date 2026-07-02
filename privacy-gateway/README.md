# Policy Circuits -- Circom / Groth16 (BLS12-381)

BLS12-381 Groth16 circuits for Interlinked ZK-gated policy checks.
Compiled with --prime bls12381 and verified on Soroban using native BLS12-381 host functions.

This directory holds every policy circuit, not just one. Adding a new policy
type is a config-and-circuit step, not a pipeline rewrite -- see
ADDING A NEW POLICY TYPE below.

---

## FILES

---

- `circuits.json` -- Per-circuit metadata: prime, vk_id, public signal order, which signal is the nullifier
- `circuits/*.circom` -- One `.circom` file per policy type
- `inputs/<circuit>.json` -- Witness input template per circuit -- fill before running
- `prove.sh` -- Full pipeline (Linux/macOS)
- `prove.ps1` -- Full pipeline (Windows PowerShell)
- `fix_snarkjs_path.ps1` -- One-time Windows PATH diagnostic + fix
- `scripts/circuit_meta.mjs` -- Shared circuits.json loader (lib + CLI)
- `scripts/encode_for_soroban.mjs` -- Converts snarkjs JSON to Soroban BytesN hex args
- `target/pot/` -- Powers of Tau ceremony output, shared by all circuits of the same prime
- `target/<circuit>/` -- Per-circuit build artifacts (r1cs, wasm, zkey, verification_key.json, proof.json, public.json, soroban_args.json)

---

## ADDING A NEW POLICY TYPE

---

1. Write `circuits/<name>.circom`. Public inputs are circuit-specific, but
   every circuit must declare a nullifier signal among them for replay
   protection.

2. Add an entry to `circuits.json`:

   ```json
   "<name>": {
     "prime": "bls12381",
     "vk_id": "<name>_v1",
     "public_signals": ["..."],
     "nullifier_signal": "nullifier_hash"
   }
   ```

   `public_signals` must match the circuit's `component main { public [...] }`
   declaration order. If `bls12381`'s `pot_sizes` entry is too small for the
   new circuit's constraint count, raise it -- this re-runs the ceremony once
   for every circuit on that prime, so size it generously up front (see
   POWERS OF TAU SIZING below).

3. Add `inputs/<name>.json` with placeholder values for every circuit input.
   `scripts/prepare_witness_input.mjs` expands this into
   `target/<name>/witness_input.json`, which is what's actually fed to
   `generate_witness.js` -- every top-level key in *that* expanded file must
   be a real signal declared in the circuit, since the witness calculator
   binds each key directly to a signal slot and throws ("Too many values for
   input signal ...") on anything else, including documentation/comment
   keys. JSON has no comment syntax; don't add one.

   Two optional `circuits.json` blocks make the *human-authored* file looser
   than that:

   - `derived_fields` -- fields computed via `Poseidon255(a, b)` from two
     other fields (e.g. `credential_commitment` from `kyc_secret` +
     `jurisdiction`). Omit these from `inputs/<name>.json` entirely --
     `prepare_witness_input.mjs` computes and injects them, and overwrites
     them if present. This is what prevents editing `jurisdiction` or
     `context_id` from silently leaving a stale hash behind.
   - `array_fields` -- fixed-size array signals (circom arrays can't be
     variable-length) that may be authored as a comma-separated string
     (`"784,321"`) instead of a hand-padded array; unused slots are filled
     by repeating the last real value.

   See `circuits/verify_investor_jurisdiction.circom` and its `circuits.json`
   entry for a circuit using both.

4. Run the pipeline:

   ```bash
   ./prove.sh <name> all          # Linux/macOS
   ```

   ```powershell
   .\prove.ps1 -Circuit <name>    # Windows
   ```

The Powers of Tau ceremony (`target/pot/`) is only regenerated if missing --
adding circuit #2, #3, etc. skips straight to the circuit-specific groth16
setup.

---

## POWERS OF TAU SIZING

---

`circuits.json`'s `pot_sizes` maps each prime to a single power-of-two
ceremony size `n`, shared by every circuit declared with that prime. A
ceremony of size `n` supports any circuit with up to `2^n` constraints --
size it for the largest circuit on that prime, not just the one you're
currently adding.

Current value: `"bls12381": 17` (`2^17` = 131,072 constraints of headroom).
`verify_link_access` needs ~2,770 constraints (see CONSTRAINT ESTIMATE
below), so the floor is `n >= 12` (`2^12` = 4,096); `verify_investor_jurisdiction`
has no Merkle path and needs far fewer. 17 leaves comfortable room for
near-term additions without forcing a ceremony rebuild on every new circuit.
The previous value, 20, also worked but took noticeably longer to build for
no benefit at this circuit size -- pick the smallest `n` that comfortably
clears your largest circuit's constraint count, not the largest you can
imagine.

Two things to know before changing this number:

- The ceremony output is `target/pot/<prime>_<size>_final.ptau` --
  filenamed by size. Changing `pot_sizes.bls12381` does not reuse or delete
  the old file; the next pipeline run looks for the new filename, doesn't
  find it, and rebuilds the ceremony from scratch for every circuit on that
  prime. Delete the stale `<prime>_<old-size>_final.ptau` afterward.
- An interrupted `Step-Ptau` run can leave a half-finished
  `target/pot/pot_0000.ptau` (and/or `pot_0001.ptau`) behind -- these are
  intermediate files reused on every `powersoftau new` call regardless of
  size, so a fresh run silently overwrites them. Safe to delete manually if
  you want to confirm a clean rebuild.

---

## CIRCUIT DESIGN -- verify_link_access

---

A single Groth16 proof simultaneously proves three things:

1. KYC GROUP MEMBERSHIP
   The prover's credential leaf is a member of the on-chain Merkle tree.
   Leaf = Poseidon255(kyc_secret, wallet_address, jurisdiction, accredited)

2. POLICY SATISFACTION
   The credential encodes the required jurisdiction and accredited values
   for this link's access policy.

3. NULLIFIER BINDING
   nullifier_hash = Poseidon255(kyc_secret, link_id)
   The on-chain contract stores this after first use to prevent replay.
   Because the nullifier is link-scoped, the same credential produces a
   different nullifier for every distinct gated link.

PUBLIC INPUTS (5 signals -- seen by the on-chain verifier)

- `merkle_root` -- Current KYC tree root stored on-chain
- `nullifier_hash` -- Replay-prevention tag stored on-chain after first use
- `link_id` -- Gated link shortcode as a field element
- `policy_jurisdiction` -- Required jurisdiction code (0 = no restriction)
- `policy_accredited` -- Required accreditation flag (0 = not required, 1 = required)

PRIVATE INPUTS (never revealed)

- `kyc_secret` -- Secret known only to the credential holder
- `wallet_address` -- Prover wallet -- binds proof to identity
- `jurisdiction` -- Actual jurisdiction code in the credential
- `accredited` -- Actual accreditation bit (0 or 1)
- `path_elements[20]` -- Merkle sibling hashes
- `path_indices[20]` -- Merkle path direction bits (0 = left, 1 = right)

HASH FUNCTION
Poseidon255 from poseidon-bls12381-circom.
The standard circomlib Poseidon uses BN254 constants -- do NOT use it here.

TREE DEPTH
depth = 20 supports up to 2^20 (~1 million) credentials.
Reduce to 16 for faster proving during development.

CONSTRAINT ESTIMATE

| Component                              | Constraints (approx) |
|----------------------------------------|----------------------|
| Leaf hash (Poseidon255 arity 4)        | 240                  |
| Merkle path (20 x Poseidon255 arity 2) | 2400                 |
| Nullifier hash (Poseidon255 arity 2)   | 120                  |
| Policy + range checks                  | 10                   |
| Total                                  | ~2770                |

Groth16 proof size (BLS12-381): ~800 bytes.
On-chain verification: 4 pairings via Soroban pairing_check -- within 100M instruction budget.

---

## CIRCUIT DESIGN -- verify_investor_jurisdiction

---

Proves a prover's private `jurisdiction` either is or is not a member of a
private allow-list (`policy_jurisdiction[8]`), WITHOUT revealing
`jurisdiction` or the list itself on-chain, AND without the prover being
able to silently swap in a list of their own choosing.

1. CREDENTIAL BINDING

   `credential_commitment = Poseidon255(kyc_secret, jurisdiction)` -- ties
   the proof to a specific issued credential, same role as
   `verify_link_access`'s Merkle leaf but without a tree (no group
   membership claim here, just "this prover holds this credential").

2. POLICY COMMITMENT BINDING

   `policy_hash = Poseidon255(...policy_jurisdiction)` (arity-8 Poseidon over
   the full padded array) is asserted equal to a circuit input. The circuit
   alone proves nothing about WHICH list was used -- a prover could compute
   `policy_hash` from any list they like. What closes that gap is `verify`
   (verifier/src/gateway.rs's `bind_policy_hash` step): the contract admin
   registers the real `policy_hash` for a `context_id` once, out of band, and
   `verify` cross-checks the proof's `policy_hash` against that registry
   before accepting anything else. See `verifier/README.md`'s "Why
   policy_hash" for the attack this prevents.

3. MEMBERSHIP CHECK -- OUTPUT, NOT ASSERTION

   This is the part that's easy to get backwards. The naive circuit would
   assert membership directly:

   ```circom
   signal product;
   product <== diffs[0] * diffs[1] * ... ; // product of (jurisdiction - policy_jurisdiction[i])
   product === 0;                          // hard assertion
   ```

   This is wrong for this use case. A Groth16 witness must satisfy every
   constraint simultaneously or witness generation itself fails -- there is
   no proof object to hand anyone for the non-member case. That collapses
   the "tell the prover their jurisdiction isn't allowed" signal into a
   local script crash, before any verifier (on-chain or otherwise) is ever
   involved. It also means a verifier never gets to observe a rejection as a
   real event -- there's nothing to reject.

   This circuit instead computes membership as a PUBLIC OUTPUT using the
   classic circom `IsZero` pattern:

   ```circom
   template IsZero() {
       signal input in;
       signal output out;
       signal inv;
       inv <-- in != 0 ? 1 / in : 0;
       out <== -in * inv + 1;
       in * out === 0;
   }
   ```

   `IsZero` is always satisfiable for any `in` (0 or nonzero) -- it never
   blocks witness generation. The circuit feeds it the product of all
   `(jurisdiction - policy_jurisdiction[i])` differences (zero iff
   `jurisdiction` matches some slot) and wires the result straight to the
   public output `is_member`: 1 if the prover's private data is aligned
   with this policy's rules, 0 if it is not. Private data that isn't
   aligned with the policy now produces a perfectly valid witness and a
   cryptographically valid Groth16 proof -- it's just a proof that honestly
   says `is_member = 0`.

   `verify` (verifier/src/gateway.rs) is what actually rejects data that
   isn't aligned with the policy: it reads `public_inputs[vk.is_member_index]`
   and returns `Error::JurisdictionNotInPolicy` if it isn't exactly 1. This
   is the only way to get "the private data stays private, but the system
   tells you it's invalid" without making the private value public: the
   accept/reject decision is deferred from witness generation (which can't
   selectively fail without revealing that a private check failed) to the
   verifier (which can reject a fully-formed, valid proof on `is_member`'s
   value alone, the same way it already rejects an invalid `policy_hash` or
   replayed `nullifier_hash`).

   Soundness note: a prover cannot forge `is_member = 1` on a proof whose
   private witness actually computed 0 -- Groth16's pairing check verifies
   that proof against ALL public inputs/outputs the prover claims,
   `is_member` included. Claiming a different `is_member` value than what
   the witness actually computed makes the proof fail `pairing_check`,
   identically to claiming a wrong `nullifier_hash` or `policy_hash`.

PUBLIC SIGNALS (order matters -- circom places `main`'s OUTPUTS before its
declared `public [...]` INPUTS; verified empirically via the compiled
`.sym` file, never assumed)

- `is_member` (output) -- 1 if the prover's private data is aligned with
  this policy's rules, 0 if it is not. Always present and always either 0
  or 1 by construction.
- `credential_commitment` -- see CREDENTIAL BINDING above
- `policy_hash` -- see POLICY COMMITMENT BINDING above
- `nullifier_hash` -- `Poseidon255(kyc_secret, context_id)`, replay
  protection, same role as `verify_link_access`
- `context_id` -- which gated resource/policy this proof is for; looked up
  against the `PolicyHash` registry

PRIVATE INPUTS (never revealed)

- `kyc_secret`
- `jurisdiction`
- `policy_jurisdiction[8]`

---

## PREREQUISITES

---

| Tool        | Version  | Install                                                                     |
|-------------|----------|-----------------------------------------------------------------------------|
| circom      | >= 2.0.6 | Linux/WSL2: `cargo install circom`                                          |
| snarkjs     | >= 0.7   | `npm install -g snarkjs`                                                    |
| Node.js     | >= 18    | <https://nodejs.org>                                                        |
| stellar-cli | latest   | <https://developers.stellar.org/docs/tools/developer-tools/cli/stellar-cli> |

NOTE (Windows): `prove.ps1` uses the native Windows binary vendored at
`.\tools\circom.exe` (download from <https://github.com/iden3/circom/releases>
if missing). It falls back to a `circom.exe` on PATH otherwise -- WSL2 is
not required.

Set environment variables before running the deploy steps:

```bash
# Linux/macOS
export CONTRACT_ID=<your-soroban-contract-id>
export DEPLOYER_SECRET=<stellar-account-secret>
```

```powershell
# Windows PowerShell
$env:CONTRACT_ID = "<your-soroban-contract-id>"
$env:DEPLOYER_SECRET = "<stellar-account-secret>"
```

---

## QUICKSTART -- LINUX / MACOS

---

1. Install Node dependencies:

   ```bash
   npm install poseidon-bls12381-circom
   ```

2. Edit `inputs/<circuit>.json` with real values (see FIELD ENCODING below),
   e.g. `inputs/verify_link_access.json`.

3. Set env vars:

   ```bash
   export CONTRACT_ID=<contract-id>
   export DEPLOYER_SECRET=<secret>
   ```

4. Run the full pipeline (compile + setup + prove + encode + deploy):

   ```bash
   chmod +x prove.sh
   ./prove.sh verify_link_access all
   ```

5. Subsequent runs -- proof generation only (skips compile + ceremony):

   ```bash
   ./prove.sh verify_link_access prove
   ```

6. Local snarkjs verification only:

   ```bash
   ./prove.sh verify_link_access verify
   ```

7. Re-encode existing proof/vk without re-proving:

   ```bash
   ./prove.sh verify_link_access encode
   ```

---

## QUICKSTART -- WINDOWS (POWERSHELL)

---

1. Install Node dependencies:

   ```powershell
   npm install poseidon-bls12381-circom
   ```

2. Install snarkjs globally:

   ```powershell
   npm install -g snarkjs
   ```

3. If snarkjs is not found, run the path fix script (one time only), then
   close and reopen PowerShell before continuing:

   ```powershell
   .\fix_snarkjs_path.ps1
   ```

4. Make sure `.\tools\circom.exe` exists (download from
   <https://github.com/iden3/circom/releases> if it doesn't).

5. Allow script execution if not already set (run once as Administrator):

   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

6. Edit `inputs/<circuit>.json` with real values (see FIELD ENCODING below),
   e.g. `inputs/verify_link_access.json`.

7. Set env vars:

   ```powershell
   $env:CONTRACT_ID = "<contract-id>"
   $env:DEPLOYER_SECRET = "<secret>"
   ```

8. Run the full pipeline:

   ```powershell
   .\prove.ps1 -Circuit verify_link_access
   ```

   Subsequent runs -- proof generation only:

   ```powershell
   .\prove.ps1 -Circuit verify_link_access -Step prove
   ```

   Local snarkjs verification only:

   ```powershell
   .\prove.ps1 -Circuit verify_link_access -Step verify
   ```

   Re-encode existing proof/vk without re-proving:

   ```powershell
   .\prove.ps1 -Circuit verify_link_access -Step encode
   ```

---

## WINDOWS TROUBLESHOOTING

---

**PROBLEM:** `snarkjs : The term 'snarkjs' is not recognized...`

CAUSE: npm installs global CLI tools as `.cmd` files under the npm prefix
directory (e.g. `C:\Users\<you>\AppData\Roaming\npm\snarkjs.cmd`). This
directory may not be in your PowerShell PATH.

FIX 1 (automatic): Run `.\fix_snarkjs_path.ps1`. It locates `snarkjs.cmd`,
adds the npm prefix to your user PATH, and tests that snarkjs is callable.
Restart PowerShell after running it.

FIX 2 (manual): Find the npm prefix, then add it to PATH:

```powershell
npm config get prefix
[System.Environment]::SetEnvironmentVariable(
    "PATH",
    $env:PATH + ";<output-from-above>",
    "User"
)
```

Restart PowerShell.

FIX 3 (session only, no PATH change):

```powershell
$env:PATH += ";" + (& npm config get prefix 2>&1 | Where-Object { $_ -notmatch '^npm' }).Trim()
```

This works for the current session only.

NOTE: `prove.ps1` resolves `snarkjs.cmd` via `npm config get prefix` at
startup and calls it by full path, so it works even without a PATH fix. If
`prove.ps1` still fails, run `fix_snarkjs_path.ps1` to confirm the install is
present.

---

**PROBLEM:** `node.exe : npm warn Unknown user config "python". This will stop working in the next major version of npm. + FullyQualifiedErrorId : NativeCommandError`

CAUSE: Two separate issues combine to produce this error:

1. Your `.npmrc` contains a `python` config key that recent npm versions no
   longer recognise. npm writes a warning to stderr.
2. PowerShell treats stderr output from native commands as an error record
   when `$ErrorActionPreference = "Stop"`, causing a NativeCommandError even
   though npm exited cleanly (code 0).

FIX (npm config): Remove the unknown key from your npm config:

```powershell
npm config delete python
npm config list
```

The warning will stop appearing.

NOTE: `prove.ps1` already works around this by using
`$ErrorActionPreference = "Continue"` and capturing npm output via `2>&1`
with explicit filtering. The NativeCommandError will not abort `prove.ps1`
even if the warning persists. Run `npm config delete python` to clean up the
warning itself.

---

**PROBLEM:** Cannot find `circom.exe`

CAUSE: `.\tools\circom.exe` is missing and there is no `circom.exe` on PATH.

FIX: Download the Windows binary from
<https://github.com/iden3/circom/releases> and place it at
`.\tools\circom.exe`. Alternatively, build it inside WSL2
(`cargo install circom`) and add a `circom.exe` wrapper to PATH --
`prove.ps1` falls back to whatever `circom.exe` it finds on PATH if
`.\tools\circom.exe` is absent.

---

**PROBLEM:** `Set-ExecutionPolicy` error when running `.ps1` files

FIX: Open PowerShell as Administrator and run:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## FIELD ENCODING

---

- `wallet_address` (verify_link_access) -- Take the Stellar public key raw
  32-byte key, interpret as big-endian integer, convert to decimal string.
- `link_id` (verify_link_access) / `context_id` (verify_investor_jurisdiction)
  -- UTF-8 bytes of the shortcode/context, zero-padded to 32 bytes,
  interpreted as big-endian integer, converted to decimal string.
- `jurisdiction` / `policy_jurisdiction` -- ISO 3166-1 numeric country code.
  Examples: UAE = 784, Thailand = 764, US = 840, Turkey = 792.
  `verify_link_access`'s `policy_jurisdiction` is a single scalar (0 = no
  restriction). `verify_investor_jurisdiction`'s `policy_jurisdiction` is a
  *private* fixed 8-element array (write it as a comma-separated string,
  e.g. `"784,321"` -- `array_fields` expands it) -- slot 0 == 0 means no
  restriction (every other slot ignored); otherwise the prover's
  `jurisdiction` must equal one of the (possibly fewer than 8) real codes in
  the array. Pad unused slots by repeating any one real allowed value, not
  with 0 -- see circuits/verify_investor_jurisdiction.circom for the
  soundness argument. The array itself never appears on-chain -- only its
  commitment, `policy_hash`, does (see ADDING A NEW POLICY TYPE and
  `verifier/README.md`'s "Why policy_hash" for why).
- `kyc_secret` -- Any random 31-byte integer for testing. In production this
  is derived from the user's KYC credential issuance flow.
- `credential_commitment` (verify_investor_jurisdiction) -- Poseidon255
  (kyc_secret, jurisdiction). `policy_hash` (verify_investor_jurisdiction) --
  Poseidon255(...policy_jurisdiction). Both are `derived_fields` --
  `prepare_witness_input.mjs` computes and injects them automatically; omit
  them from `inputs/<name>.json` entirely.
- `gated_link_url` / `gated_link_content_type` -- plain strings, NOT circuit
  signals (they're stripped from `witness_input.json` before the witness
  calculator ever sees them, since it throws on any key that isn't a real
  signal). Read directly by `prove.ps1`/`prove.sh`'s `Step-CreateGatedLink`/
  `step_create_gated_link` to call `create_gated_link(url, content_type,
  policy_hash, vk_id)` on the gated-link contract `$env:CONTRACT_ID` points
  at -- required for any circuit with a `policy_hash` binding when running
  `-Step all`/`prove`. That contract's returned `code_link` then becomes
  `context_id` for the actual proof (see PIPELINE STEPS below) -- there is
  no manual `-ContextLink` step in `all`/`prove`, only in `local`.

---

## SOROBAN BYTE LAYOUT

---

Soroban BLS12-381 host functions expect uncompressed big-endian points:

| Type               | Size          | Layout                                     |
|--------------------|---------------|--------------------------------------------|
| `Bls12381G1Affine` | `BytesN<96>`  | `[x: 48 bytes][y: 48 bytes]`               |
| `Bls12381G2Affine` | `BytesN<192>` | `[x_c1: 48][x_c0: 48][y_c1: 48][y_c0: 48]` |
| `Bls12381Fr`       | `BytesN<32>`  | 32-byte big-endian scalar                  |

`encode_for_soroban.mjs` converts snarkjs JSON output to these layouts
automatically. Verify the G2 byte order against the Soroban BLS12-381 host
function documentation before the first Testnet run -- a byte-order mismatch
in G2 is the most likely failure mode.

---

## PIPELINE STEPS

---

| Step                | Script function       | Description                                                                  |
|---------------------|------------------------|--------------------------------------------------------------------------------|
| deps                | `Step-Deps`            | `npm install poseidon-bls12381-circom`                                       |
| compile             | `Step-Compile`         | `circom --prime bls12381` -> `.r1cs` + `.wasm`                               |
| ptau                | `Step-Ptau`            | Powers of Tau BLS12-381 ceremony (shared, skipped if already built)          |
| setup               | `Step-Setup`           | Groth16 circuit-specific trusted setup                                       |
| (create_gated_link) | `Step-CreateGatedLink` | Derives policy_hash (pre-pass), calls `create_gated_link`, then proves with `context_id = code_link` |
| prove               | `Step-Prove`           | Witness generation + proof generation (`local` step only; `all`/`prove` go through `Step-CreateGatedLink` instead) |
| verify              | `Step-Verify`          | Local snarkjs verification                                                   |
| encode              | `Step-Encode`          | Convert to Soroban BytesN hex args                                           |
| deploy_vk           | `Step-DeployVk`        | Upload VK to contract via stellar-cli (`set_verifying_key`)                  |
| (onchain)           | `Step-OnchainVerify`   | Calls `resolve_gated_link(code_link, proof_a, proof_b, proof_c, public_inputs)` on Testnet |

`Step-CreateGatedLink`/`step_create_gated_link` and the `resolve_gated_link`
call in `Step-OnchainVerify`/`step_onchain_verify` target a *different*
deployed contract's ABI than `verifier/`'s own `register_policy_hash`/
`verify` (which this pipeline used before) -- `create_gated_link(url,
content_type, policy_hash, vk_id) -> code_link` and `resolve_gated_link
(code_link, proof_a, proof_b, proof_c, public_inputs)`, where `vk_id` is
looked up server-side from the link record instead of being a `verify`-time
argument. `$env:CONTRACT_ID` must point at a contract exposing these two
functions, not at a plain `verifier`/`register_policy_hash` deployment.
`gated_link_url`/`gated_link_content_type` (see FIELD ENCODING above) are
required in `inputs/<circuit>.json` for any circuit with a `policy_hash`
binding when running `-Step all`/`prove`.

The ptau step is slow (minutes) but runs once per prime across all circuits,
not once per circuit -- it is skipped automatically once
`target/pot/<prime>_<size>_final.ptau` exists. The setup step still runs once
per circuit. After a circuit's `.zkey` files exist, use
`./prove.sh <circuit> prove` or `.\prove.ps1 -Circuit <circuit> -Step prove`
for all subsequent proof generations.

`<circuit> local` / `-Step local` runs only `Step-Prove` + `Step-Verify` --
witness generation and local snarkjs verification from whatever is currently
in `inputs/<circuit>.json`, with zero network or contract calls (no
`create_gated_link`, no `resolve_gated_link`). Use this to iterate on
`jurisdiction` / `policy_jurisdiction` values: edit the JSON, rerun `local`
(optionally with `-ContextLink <string>` to pick a specific context_id), and
read `is_member` out of `target/<circuit>/public.json` (see CIRCUIT DESIGN
-- verify_investor_jurisdiction below for why data that isn't aligned with
the policy still produces a valid proof here instead of a
witness-generation error). `prove` and `all` both go on to
create_gated_link/deploy_vk/resolve_gated_link -- use `local` when you
specifically want to stay offline.
