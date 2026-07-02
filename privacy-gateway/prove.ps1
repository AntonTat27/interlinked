# =============================================================================
# Interlinked -- policy circuit proof pipeline (Windows PowerShell)
# BLS12-381 Groth16 via Circom + snarkjs
#
# Supports any circuit listed in circuits.json. The Powers of Tau ceremony is
# shared across all circuits of the same prime (run once, reused by every
# circuit's groth16 setup) -- adding a new policy circuit only re-runs
# compile + setup, never the ceremony.
#
# Prerequisites:
#   - circom >= 2.0.6   (native Windows binary in .\tools\circom.exe --
#                        download from https://github.com/iden3/circom/releases)
#   - snarkjs >= 0.7    (npm install -g snarkjs)
#   - Node.js >= 18     (https://nodejs.org)
#   - stellar-cli       (https://developers.stellar.org/docs/tools/developer-tools/cli/stellar-cli)
#   - $env:CONTRACT_ID and $env:DEPLOYER_SECRET set before running
#
# Usage:
#   .\prove.ps1 -Circuit verify_link_access              # full pipeline
#   .\prove.ps1 -Circuit verify_link_access -Step local   # regenerate witness+proof from
#                                                          # inputs/<circuit>.json and verify
#                                                          # locally -- no network/contract
#                                                          # calls at all. Use this to test
#                                                          # policy_jurisdiction/jurisdiction
#                                                          # edits.
#   .\prove.ps1 -Circuit verify_link_access -Step prove   # proof generation, then ALSO
#                                                          # encode + call the on-chain contract
#   .\prove.ps1 -Circuit verify_link_access -Step verify  # re-verify the existing proof.json
#                                                          # locally, without regenerating it
#   .\prove.ps1 -Circuit verify_link_access -Step encode  # re-encode existing proof/vk only
#   .\prove.ps1 -Circuit verify_investor_jurisdiction -Step local `
#       -ContextLink <any shortcode/URL>
#                                                          # use an arbitrary string as
#                                                          # context_id instead of
#                                                          # inputs/<circuit>.json's value or
#                                                          # auto_fields' random one -- for
#                                                          # offline testing only (no network
#                                                          # calls happen in -Step local).
#
#   "all"/"prove" don't take -ContextLink at all -- for circuits with a
#   policy_hash binding (like verify_investor_jurisdiction), Step-CreateGatedLink
#   calls create_gated_link itself, and the code_link it gets back becomes
#   context_id automatically (see prepare_witness_input.mjs's header comment
#   for the encoding caveat). This requires gated_link_url/gated_link_content_type
#   in inputs/<circuit>.json.
#
#   Circuit names come from circuits.json. Adding a new policy type means:
#     1. drop the .circom file in circuits/
#     2. add its entry to circuits.json
#     3. add its witness input file to inputs/<circuit>.json
#     4. .\prove.ps1 -Circuit <circuit>
# =============================================================================

param(
    [Parameter(Mandatory = $true)]
    [string]$Circuit,

    [ValidateSet("all", "local", "prove", "verify", "encode")]
    [string]$Step = "all",

    # Gated-link shortcode/URL to use as context_id (e.g. create_gated_link's
    # return value) -- overrides any context_id already in inputs/<circuit>.json
    # and skips auto_fields' random generation. See prepare_witness_input.mjs's
    # header comment for the encoding caveat (32-byte UTF-8 limit, must match
    # whatever encoded context_id on the link-creating contract's side).
    [string]$ContextLink = "",

    # Step-CreateGatedLink (-Step all only) caches the code_link it gets back
    # from create_gated_link in target/<circuit>/code_link.txt and reuses it
    # on subsequent "all" runs, so re-running "all" doesn't mint a new link
    # every time. Pass -ForceNewLink to delete the cache and create a
    # genuinely new link instead -- e.g. after changing gated_link_url/
    # gated_link_content_type, which the cache does NOT detect on its own.
    # "prove" always reuses the cache and never creates a link -- this flag
    # has no effect under -Step prove.
    [switch]$ForceNewLink
)

Set-StrictMode -Version Latest
# Keep "Stop" for our own throw statements but DO NOT let npm/node stderr
# warnings abort the script.  Native command stderr is not a terminating
# error in PowerShell -- the issue was that npm config get prefix writes
# "npm warn ..." lines to stderr which PowerShell surfaces as
# NativeCommandError when $ErrorActionPreference = "Stop".
# We handle this by capturing stdout/stderr separately and checking
# $LASTEXITCODE explicitly everywhere instead.
$ErrorActionPreference = "Stop"

$CIRCUIT = $Circuit
$META = node ./scripts/circuit_meta.mjs $CIRCUIT | ConvertFrom-Json
$PRIME = $META.prime
$POT_SIZE = $META.pot_size
$VK_ID = $META.vk_id

# Set by Step-CreateGatedLink, read by Step-OnchainVerify -- initialized here
# so Set-StrictMode doesn't throw on the unset-variable read in
# Step-OnchainVerify's guard check when Step-CreateGatedLink hasn't run yet
# (e.g. -Step verify/encode).
$script:CODE_LINK = $null

# Forward slashes only -- these paths get embedded inside JS string literals
# in Step-DeployVk/Step-OnchainVerify's `node -e "...require('...')..."`
# calls. A literal "\t" or "\v" from a Windows backslash path (e.g. from
# "target" or "verify_...") is interpreted by Node's JS parser as an escape
# sequence (tab / vertical-tab), silently corrupting the path. Forward
# slashes are accepted everywhere on Windows and have no escape meaning.
$DIR_OUT = "./target/$CIRCUIT"
$POT_DIR = "./target/pot"
$POT_FINAL = "$POT_DIR/${PRIME}_${POT_SIZE}_final.ptau"
$INPUT_FILE = "./inputs/$CIRCUIT.json"

# Fallback testnet deployer identity, used only when $env:CONTRACT_ID/
# $env:DEPLOYER_SECRET aren't provided via the environment. Committed to
# source control -- treat as a shared/throwaway testnet identity, never
# reuse it for anything holding real value.
$DEFAULT_CONTRACT_ID = "CCBGT2AD2GW5UCNFVP6WA46LK6CDDEUSFQBWF6EKEX5T63TA3L2RLPND"
$DEFAULT_DEPLOYER_SECRET = "SD4YG42JMHV76CSDGVVXN5QWT6NOKXQP75ESLYBKKVF7CN2O7VXEUYSE"

# Called by Step-CreateGatedLink/Step-DeployVk (the only steps that talk to
# the contract) instead of hard-erroring when $env:CONTRACT_ID/
# $env:DEPLOYER_SECRET are absent -- falls back to the default testnet
# identity above.
function Require-ContractCreds {
    if (-not $env:CONTRACT_ID) {
        Write-Warning "CONTRACT_ID not set -- using default testnet contract: $DEFAULT_CONTRACT_ID"
        $env:CONTRACT_ID = $DEFAULT_CONTRACT_ID
    }
    if (-not $env:DEPLOYER_SECRET) {
        Write-Warning "DEPLOYER_SECRET not set -- using default testnet deployer secret"
        $env:DEPLOYER_SECRET = $DEFAULT_DEPLOYER_SECRET
    }
}

# -----------------------------------------------------------------------------
# Resolve tool paths at startup
# npm installs global CLI tools as .cmd files under the npm prefix directory.
# Relying on PATH alone is unreliable on Windows -- we locate them explicitly.
#
# "npm config get prefix" prints the prefix on stdout but may also emit
# "npm warn ..." lines on stderr (e.g. unknown config keys).  We capture
# both streams, keep only the stdout lines, and strip whitespace.
# -----------------------------------------------------------------------------
function Get-NpmPrefix {
    # 2>&1 merges stderr into the output stream so we can filter it here
    # rather than letting PowerShell turn it into an error record.
    $raw = & npm config get prefix 2>&1
    # Keep only lines that do NOT look like npm warnings/errors
    $prefix = ($raw | Where-Object { $_ -notmatch '^npm (warn|error|notice)' } | Select-Object -First 1)
    if (-not $prefix) { throw "Could not determine npm prefix. Run: npm config get prefix" }
    return $prefix.Trim()
}

function Resolve-NpmBin {
    param([string]$ToolName)
    $prefix = Get-NpmPrefix
    $cmd = Join-Path $prefix "${ToolName}.cmd"
    if (Test-Path $cmd) { return $cmd }
    # Fallback: some npm versions nest binaries under bin\
    $cmd2 = Join-Path $prefix "bin\${ToolName}.cmd"
    if (Test-Path $cmd2) { return $cmd2 }
    throw "Cannot find ${ToolName}.cmd under npm prefix '$prefix'. Run: npm install -g $ToolName"
}

function Resolve-Circom {
    # Prefer the native Windows binary vendored under .\tools -- avoids
    # depending on WSL2 (which may not have a usable Linux distro installed).
    $local = Join-Path $PSScriptRoot "tools\circom.exe"
    if (Test-Path $local) { return $local }
    $onPath = Get-Command circom.exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    throw "Cannot find circom.exe. Download the Windows binary from " + `
        "https://github.com/iden3/circom/releases and place it at " + `
        "${PSScriptRoot}\tools\circom.exe"
}

Write-Host "-> resolving tool paths..."
$SNARKJS = Resolve-NpmBin "snarkjs"
Write-Host "   snarkjs  : $SNARKJS"
$CIRCOM = Resolve-Circom
Write-Host "   circom   : $CIRCOM"
Write-Host "   circuit  : $CIRCUIT (vk_id: $VK_ID, prime: $PRIME, pot_size: $POT_SIZE)"

function Invoke-Circom {
    & $CIRCOM @args
    if ($LASTEXITCODE -ne 0) { throw "circom failed (exit $LASTEXITCODE)" }
}

# Wrapper so we can write `Invoke-Snarkjs groth16 prove ...` throughout
function Invoke-Snarkjs {
    & $SNARKJS @args
    if ($LASTEXITCODE -ne 0) { throw "snarkjs $($args[0]) failed (exit $LASTEXITCODE)" }
}

# -----------------------------------------------------------------------------

function Step-Deps {
    Write-Host "-> installing poseidon-bls12381-circom..."
    npm install poseidon-bls12381-circom
    if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
}

function Step-Compile {
    Write-Host "-> compiling circuits\${CIRCUIT}.circom (prime: ${PRIME})..."
    New-Item -ItemType Directory -Force -Path $DIR_OUT | Out-Null

    Invoke-Circom "circuits\${CIRCUIT}.circom" `
        --r1cs --wasm --sym `
        --prime $PRIME `
        -l ".\node_modules" `
        --output $DIR_OUT

    $info = Invoke-Snarkjs r1cs info "${DIR_OUT}\${CIRCUIT}.r1cs" 2>&1
    Write-Host ($info | Select-String "constraints")
}

function Step-Ptau {
    if (Test-Path $POT_FINAL) {
        Write-Host "-> reusing existing Powers of Tau: $POT_FINAL"
        return
    }
    Write-Host "-> powers of tau (${PRIME}, size ${POT_SIZE})..."
    New-Item -ItemType Directory -Force -Path $POT_DIR | Out-Null
    $entropy1 = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
    Invoke-Snarkjs powersoftau new $PRIME $POT_SIZE "${POT_DIR}\pot_0000.ptau" -v
    Invoke-Snarkjs powersoftau contribute `
        "${POT_DIR}\pot_0000.ptau" `
        "${POT_DIR}\pot_0001.ptau" `
        --name="interlinked-setup-1" "-e=$entropy1"
    Invoke-Snarkjs powersoftau prepare phase2 `
        "${POT_DIR}\pot_0001.ptau" `
        $POT_FINAL -v
    Remove-Item -Force "${POT_DIR}\pot_0000.ptau", "${POT_DIR}\pot_0001.ptau" -ErrorAction SilentlyContinue
}

function Step-Setup {
    Write-Host "-> groth16 setup for ${CIRCUIT} (vk_id: ${VK_ID})..."
    $entropy2 = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
    Invoke-Snarkjs groth16 setup `
        "${DIR_OUT}\${CIRCUIT}.r1cs" `
        $POT_FINAL `
        "${DIR_OUT}\${CIRCUIT}_0000.zkey"
    Invoke-Snarkjs zkey contribute `
        "${DIR_OUT}\${CIRCUIT}_0000.zkey" `
        "${DIR_OUT}\${CIRCUIT}_final.zkey" `
        --name="interlinked-circuit-1" "-e=$entropy2"
    Invoke-Snarkjs zkey export verificationkey `
        "${DIR_OUT}\${CIRCUIT}_final.zkey" `
        "${DIR_OUT}\verification_key.json"
    Write-Host "-> verification key written to ${DIR_OUT}\verification_key.json"
}

function Step-Prove {
    # ContextLinkOverride lets Step-CreateGatedLink feed in the code_link it
    # just got back from create_gated_link, without the caller having to
    # also pass -ContextLink manually on the same invocation. An explicit
    # -ContextLink (the top-level param) is used otherwise.
    #
    # FreshKycSecret regenerates kyc_secret (see prepare_witness_input.mjs's
    # header comment for why) -- used whenever re-proving against an
    # ALREADY-cached code_link, so the resulting nullifier_hash differs from
    # whatever was already submitted on-chain for that context_id.
    param(
        [string]$ContextLinkOverride = "",
        [switch]$FreshKycSecret
    )
    $effectiveContextLink = if ($ContextLinkOverride) { $ContextLinkOverride } else { $ContextLink }

    Write-Host "-> generating witness..."
    # Derives circuits.json derived_fields (e.g. credential_commitment from
    # kyc_secret + jurisdiction) and expands array_fields (e.g.
    # policy_jurisdiction: "784,321" into the fixed-size padded array). No-op
    # for circuits with neither.
    $prepareArgs = @($CIRCUIT, $INPUT_FILE, "${DIR_OUT}/witness_input.json")
    if ($effectiveContextLink -or $FreshKycSecret) { $prepareArgs += $effectiveContextLink }
    if ($FreshKycSecret) { $prepareArgs += "1" }
    node ./scripts/prepare_witness_input.mjs @prepareArgs
    if ($LASTEXITCODE -ne 0) { throw "prepare_witness_input.mjs failed" }
    node "${DIR_OUT}\${CIRCUIT}_js\generate_witness.js" `
        "${DIR_OUT}\${CIRCUIT}_js\${CIRCUIT}.wasm" `
        "${DIR_OUT}/witness_input.json" `
        "${DIR_OUT}\witness.wtns"
    if ($LASTEXITCODE -ne 0) { throw "witness generation failed" }

    Write-Host "-> generating groth16 proof (${PRIME})..."
    Invoke-Snarkjs groth16 prove `
        "${DIR_OUT}\${CIRCUIT}_final.zkey" `
        "${DIR_OUT}\witness.wtns" `
        "${DIR_OUT}\proof.json" `
        "${DIR_OUT}\public.json"
}

function Step-Verify {
    Write-Host "-> verifying locally with snarkjs..."
    Invoke-Snarkjs groth16 verify `
        "${DIR_OUT}\verification_key.json" `
        "${DIR_OUT}\public.json" `
        "${DIR_OUT}\proof.json"
    Write-Host "OK local verification passed"
}

function Step-Encode {
    Write-Host "-> encoding proof + VK for Soroban BLS12-381 layout..."
    node ".\scripts\encode_for_soroban.mjs" $CIRCUIT
    if ($LASTEXITCODE -ne 0) { throw "encode_for_soroban.mjs failed" }
}

function Step-DeployVk {
    Write-Host "-> uploading verifying key to contract (vk_id: ${VK_ID})..."
    Require-ContractCreds
    # set_verifying_key_argv is a flat JSON array of argv tokens -- ConvertFrom-Json
    # gives a PowerShell array, and @invokeArgs (splat) expands each element as a
    # separate native-command argument. This avoids ever re-parsing a combined
    # string, which is what broke here previously (JSON.stringify of the whole
    # args object was passed as a single argument and rejected by the CLI).
    #
    # --ic's value is itself a JSON array string (embedded double quotes, e.g.
    # ["aabb...","ccdd..."]) -- PowerShell's native-command argument marshalling
    # silently strips embedded `"` characters when building the child process's
    # command line. Pre-escaping each `"` as `\"` survives that marshalling and
    # is correctly un-escaped back to a literal `"` by the receiving process's
    # own argv parsing (standard Win32 command-line convention), so stellar
    # sees the original valid JSON. Escaping is a no-op on tokens with no
    # quotes, so it's applied uniformly rather than special-cased per flag.
    $invokeArgs = node -e "const a=require('./${DIR_OUT}/soroban_args.json');process.stdout.write(JSON.stringify(a.set_verifying_key_argv));" | ConvertFrom-Json
    $invokeArgs = $invokeArgs | ForEach-Object { $_.Replace('"', '\"') }
    stellar contract invoke `
        --id $env:CONTRACT_ID `
        --source $env:DEPLOYER_SECRET `
        --network testnet `
        -- set_verifying_key  @invokeArgs
    if ($LASTEXITCODE -ne 0) { throw "set_verifying_key failed" }
    Write-Host "OK verifying key uploaded"
}

# Used only by "prove" -- re-generates the proof against an ALREADY-created
# gated link's cached code_link, on the basis of whatever jurisdiction/
# policy_jurisdiction currently is in inputs/<circuit>.json. There is no
# link-creation code path in this function at all (not just a guarded one):
# "prove" calling this function makes it structurally impossible for it to
# ever mint a new link, regardless of flags or cache state.
function Step-ReproveExistingLink {
    $codeLinkCacheFile = "${DIR_OUT}/code_link.txt"
    if (-not (Test-Path $codeLinkCacheFile)) {
        throw "no gated link exists yet for ${CIRCUIT} (${codeLinkCacheFile} not found) -- run '.\prove.ps1 -Circuit ${CIRCUIT} -Step all' once first to create one, then use -Step prove for subsequent runs"
    }
    $script:CODE_LINK = (Get-Content $codeLinkCacheFile -Raw).Trim()
    Write-Host "-> reusing cached gated link: $($script:CODE_LINK)"
    # gated_link_url/content_type/policy_hash were fixed when the link was
    # created; jurisdiction/policy_jurisdiction are free to have changed
    # since -- that's the whole point of this step. -FreshKycSecret avoids
    # NullifierAlreadyUsed: same context_id + same kyc_secret would otherwise
    # produce the exact nullifier_hash already consumed by an earlier
    # successful on-chain call against this same code_link.
    Step-Prove -ContextLinkOverride $script:CODE_LINK -FreshKycSecret
}

# Used only by "all" -- creates a gated link if none is cached yet (or
# -ForceNewLink was passed), or reuses the cached one otherwise, then proves
# against whichever code_link results.
function Step-CreateGatedLink {
    Require-ContractCreds

    $codeLinkCacheFile = "${DIR_OUT}/code_link.txt"
    if ($ForceNewLink -and (Test-Path $codeLinkCacheFile)) {
        Remove-Item $codeLinkCacheFile -Force
    }
    if (Test-Path $codeLinkCacheFile) {
        $script:CODE_LINK = (Get-Content $codeLinkCacheFile -Raw).Trim()
        Write-Host "-> reusing cached gated link: $($script:CODE_LINK) (delete ${codeLinkCacheFile} or pass -ForceNewLink for a new one)"
        # -FreshKycSecret avoids NullifierAlreadyUsed -- see
        # Step-ReproveExistingLink's comment for why.
        Step-Prove -ContextLinkOverride $script:CODE_LINK -FreshKycSecret
        return
    }

    Write-Host "-> deriving policy_hash (pre-pass, no proof generated yet)..."
    # policy_hash only depends on policy_jurisdiction, never on context_id,
    # so it's safe to compute before we know what code_link create_gated_link
    # will return -- this avoids generating a real (expensive) proof twice:
    # once to learn policy_hash, once more with the real context_id.
    node ./scripts/prepare_witness_input.mjs $CIRCUIT $INPUT_FILE "${DIR_OUT}/witness_input_prepass.json"
    if ($LASTEXITCODE -ne 0) { throw "prepare_witness_input.mjs (pre-pass) failed" }
    $prepass = Get-Content "${DIR_OUT}/witness_input_prepass.json" -Raw | ConvertFrom-Json
    if (-not $prepass.policy_hash) {
        throw "circuit ${CIRCUIT} has no policy_hash field -- create_gated_link needs one (see circuits.json derived_fields)"
    }
    # Same decimal-string -> 32-byte big-endian hex conversion as
    # encode_for_soroban.mjs's decToHex -- policy_hash here is a BytesN<32>
    # argument, same as everywhere else in this pipeline.
    $policyHashHex = node -e "process.stdout.write(BigInt(process.argv[1]).toString(16).padStart(64, '0'))" $prepass.policy_hash

    $rawInput = Get-Content $INPUT_FILE -Raw | ConvertFrom-Json
    if (-not $rawInput.gated_link_url -or -not $rawInput.gated_link_content_type) {
        throw "inputs/${CIRCUIT}.json needs gated_link_url and gated_link_content_type to call create_gated_link"
    }

    Write-Host "-> calling create_gated_link (vk_id: ${VK_ID})..."
    # NOTE: assumes `stellar contract invoke` prints a String return value as
    # its last stdout line, quoted -- verify this against actual CLI output
    # the first time this runs; adjust the trim/parse below if the format
    # differs.
    $invokeOutput = stellar contract invoke `
        --id $env:CONTRACT_ID `
        --source $env:DEPLOYER_SECRET `
        --network testnet `
        -- create_gated_link `
        --url $rawInput.gated_link_url `
        --content_type $rawInput.gated_link_content_type `
        --policy_hash $policyHashHex `
        --vk_id $VK_ID
    if ($LASTEXITCODE -ne 0) { throw "create_gated_link failed" }
    $createdUrl = ($invokeOutput | Select-Object -Last 1).Trim('"')
    # create_gated_link returns the full URL (e.g. "https://base.url/!e") --
    # resolve_gated_link's code_link parameter, and context_id, need just the
    # shortcode suffix after the last "/", not the whole URL.
    $script:CODE_LINK = $createdUrl.Substring($createdUrl.LastIndexOf('/') + 1)
    Set-Content -Path $codeLinkCacheFile -Value $script:CODE_LINK -NoNewline
    Write-Host "OK gated link created: ${createdUrl} (code_link: $($script:CODE_LINK), cached at ${codeLinkCacheFile})"

    # Now run the REAL proving step with context_id = code_link, so the
    # proof actually submitted to resolve_gated_link is scoped to this link
    # -- not the throwaway/random context_id the pre-pass above used.
    Step-Prove -ContextLinkOverride $script:CODE_LINK
}

function Step-OnchainVerify {
    if (-not $script:CODE_LINK) {
        throw "no code_link available -- run Step-CreateGatedLink first (resolve_gated_link needs it)"
    }
    Write-Host "-> calling resolve_gated_link on Testnet (code_link: $($script:CODE_LINK))..."
    # See Step-DeployVk for why each token is quote-escaped before the splat
    # (--public_inputs here carries the same embedded-JSON-quotes issue).
    $invokeArgs = node -e "const a=require('./${DIR_OUT}/soroban_args.json');process.stdout.write(JSON.stringify(a.resolve_gated_link_argv));" | ConvertFrom-Json
    $invokeArgs = $invokeArgs | ForEach-Object { $_.Replace('"', '\"') }
    stellar contract invoke `
        --id $env:CONTRACT_ID `
        --source $env:DEPLOYER_SECRET `
        --network testnet `
        -- resolve_gated_link --code_link $script:CODE_LINK @invokeArgs
    if ($LASTEXITCODE -ne 0) { throw "resolve_gated_link failed" }
    Write-Host "OK resolve_gated_link passed"
}

# -- Entrypoint ----------------------------------------------------------------
switch ($Step) {
    "all" {
        # "all" rebuilds everything from scratch (compile/ptau/setup), so any
        # code_link.txt left over from a previous run is stale by
        # definition (it may have been registered against an old circuit
        # version's verifying key) -- always start fresh here, unlike
        # Step-CreateGatedLink's own cache check (which "all" effectively
        # bypasses via this deletion, but is still safe to leave in place
        # for clarity/defense in depth).
        $codeLinkCacheFile = "${DIR_OUT}/code_link.txt"
        if (Test-Path $codeLinkCacheFile) { Remove-Item $codeLinkCacheFile -Force }

        Step-Deps
        Step-Compile
        Step-Ptau
        Step-Setup
        Step-CreateGatedLink
        Step-Verify
        Step-Encode
        Step-DeployVk
        Step-OnchainVerify
    }
    "local" {
        Step-Prove
        Step-Verify
    }
    "prove" {
        Step-ReproveExistingLink
        Step-Verify
        Step-Encode
        Step-DeployVk
        Step-OnchainVerify
    }
    "verify" { Step-Verify }
    "encode" { Step-Encode }
}
