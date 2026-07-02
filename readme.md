# Interlinked — Soroban Multi-Tenant Link Shortener with ZK-Gated Access

A secure and scalable link shortening service built on Soroban smart contracts, with multi-tenancy support and
zero-knowledge-gated links via the Privacy Gateway.

- Full project documentation: <https://interlinked-1.gitbook.io/interlinked-docs>
- ZK Privacy Gateway documentation: <https://interlinked-1.gitbook.io/interlinked-docs/projects/zk-privacy-gateway>

## Privacy Gateway

[`privacy-gateway/`](privacy-gateway/) is the off-chain half of ZK-gated links: it holds the Circom circuits, the
Groth16 (BLS12-381) trusted-setup/proving pipeline, and the scripts that turn a proof into the exact byte layout the
`interlinked` contract's on-chain verifier expects. It does not run on-chain — it produces the artifacts
(`verifying key`, `proof`, `public_inputs`) that get submitted to the contract.

How it fits together:

1. **Circuit** (`privacy-gateway/circuits/*.circom`) encodes an access policy, e.g. "prover holds a KYC credential in
   a Merkle tree AND that credential satisfies a jurisdiction/accreditation rule". Every circuit exposes a
   `nullifier_hash` public signal for replay protection, and policy-bound circuits additionally expose a
   `policy_hash` + `context_id` pair so the prover cannot swap in a different rule set than the one actually
   registered for that resource.
2. **Gated link creation** — the resource owner calls the contract's `create_gated_link` with the destination URL,
   content type, a `policy_hash` (a Poseidon commitment to the real allow-list, computed off-chain) and the `vk_id`
   of the circuit that will gate it. This returns a `code_link`, which becomes the circuit's `context_id`.
3. **Proving** — `privacy-gateway/prove.sh` / `prove.ps1` run the full pipeline (compile → Powers-of-Tau ceremony →
   Groth16 setup → witness generation → proof) and then `scripts/encode_for_soroban.mjs` converts the snarkjs output
   into the raw uncompressed BLS12-381 byte layout (`BytesN<96>` G1 points, `BytesN<192>` G2 points, `BytesN<32>`
   scalars) the contract's host functions expect.
4. **On-chain verification** — the contract's `set_verifying_key` registers a circuit's VK once; `resolve_gated_link`
   then takes a proof (`proof_a`, `proof_b`, `proof_c`, `public_inputs`) and:
   - looks up the nullifier from `public_inputs` and rejects if already spent (replay protection),
   - if the circuit declares one, checks the proof's `policy_hash` against the registry entry for its `context_id`,
   - if the circuit declares one, checks the `is_member` output is exactly `1` (a circuit can produce a valid proof
     that honestly reports "not a member" instead of failing witness generation — see
     [`privacy-gateway/README.md`](privacy-gateway/README.md#circuit-design----verify_investor_jurisdiction)),
   - runs the actual Groth16 pairing check via Soroban's native BLS12-381 host functions,
   - consumes the nullifier and returns the gated destination URL only on success.

Private inputs (KYC secret, wallet address, jurisdiction, Merkle path, etc.) never leave the prover's machine — only
the proof and the public signals above are submitted on-chain. See [`privacy-gateway/README.md`](privacy-gateway/README.md)
for circuit design details, adding new policy types, field encoding, and the full pipeline/CLI reference.

## Contracts

### Multi-Tenancy Contract — private repository

- Manages tenant registration and access control
- Handles tenant-specific contract deployment
- Associates public keys with tenant identifiers
- Controls admin privileges and contract upgrades

### Interlinked Contract

- Provides custom account authentication using WebAuthn — it uses the public key credentials from the WebAuthn
  device stored at contract initialization.
- Shortens URLs: permanent (`shortened`/`shortened_ext`), temporary (`temporary_link`), disposable/one-time
  (`init_disposable_link`/`disposable_link`/`resolve_disposable_link`), and ZK-gated (`create_gated_link`/
  `resolve_gated_link`, see [Privacy Gateway](#privacy-gateway) above).
- Verifies Groth16/BLS12-381 zero-knowledge proofs on-chain (`set_verifying_key`, `resolve_gated_link`) to gate link
  access without revealing the prover's private credential data.
- Manages SEP-0010-based API keys (`set_api_key_v1`/`delete_api_key_v1`) for client access control.
- Manages base URL configuration and admin/upgrade operations (`set_admin`, `upgrade`, `version`/`version_build`,
  `extend_ttl`, `extend_link_ttl`, `delete_link`).

## Dependencies

- soroban-sdk v27.0.0-rc.1
- serde v1.0.228
- serde-json-core v0.6.0

## Setup and Configuration

### Prerequisites

- Stellar network access (testnet/mainnet)
- Soroban CLI tools (`stellar contract ...`)
- For generating ZK proofs to feed `resolve_gated_link`: see [`privacy-gateway/README.md`](privacy-gateway/README.md)'s
  prerequisites (circom, snarkjs, Node.js).

### Building, Deployment and Usage

1. Configure environment variables in `contracts/interlinked/Makefile`:

| Variable           | Default Value                                            | Description                                                                                                                                                                                              |
| ------------------ | -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| BASE_URL           | <https://base.url/>                                        | Base URL for the link shortener service                                                                                                                                                                  |
| STELLAR_NETWORK    | testnet                                                  | Target Stellar network (testnet/mainnet)                                                                                                                                                                 |
| OWNER_SEED         | SD4YG42JMHV76CSDGVVXN5QWT6NOKXQP75ESLYBKKVF7CN2O7VXEUYSE | Secret key of the contract owner                                                                                                                                                                         |
| ADMIN_ADDRESS      | CBKR4W7L7C5H6SCBK2RZ2LBSKYFDVTGMJ5UAEGWL2PWQ7KLWDNK6GRVL | Admin address passed to the constructor                                                                                                                                                                  |
| CONTRACT_ADDRESS   | CCBGT2AD2GW5UCNFVP6WA46LK6CDDEUSFQBWF6EKEX5T63TA3L2RLPND | Address of the deployed contract                                                                                                                                                                         |
| PUBLIC_KEY         | (see Makefile)                                           | secp256r1 public key SEC-1 encoded, for WebAuthn                                                                                                                                                         |
| CREDENTIALS        | (see Makefile)                                           | Public key credentials from WebAuthn, base64-encoded                                                                                                                                                     |
| TEST_URL           | <https://test.test>                                        | URL used by the `shortened`/`temporary_link`/test targets                                                                                                                                                |
| URL_CODE           | bb                                                       | Custom short-code used by `shortened_ext`                                                                                                                                                                |
| APIKEY_ACCESS      | 255                                                      | Access level used by `set_api_key_v1`                                                                                                                                                                    |
| APIKEY_TTL         | 3600                                                     | TTL (ms) used by `set_api_key_v1`                                                                                                                                                                        |
| GATED_TEST_URL     | <https://sharmony.world/deal-room/123>                     | Destination URL for `create_gated_link`                                                                                                                                                                  |
| GATED_CONTENT_TYPE | deal_room                                                | Content type for `create_gated_link`                                                                                                                                                                     |
| VK_ID              | sharmony_kyc_v1                                          | Verifying key id used by `set_verifying_key`/`create_gated_link`                                                                                                                                         |
| POLICY_HASH        | (zero placeholder)                                       | Policy commitment hash used by `create_gated_link`                                                                                                                                                       |
| GATED_CODE_LINK    | !b                                                       | Short code of the gated link used by `resolve_gated_link`                                                                                                                                                |
| ZERO_G1 / ZERO_G2  | (zero placeholders)                                      | Correctly-sized but non-functional test vectors for compile/call-plumbing only — real values must come from an actual Circom proof + matching trusted-setup VK (see [Privacy Gateway](#privacy-gateway)) |
| NULLIFIER          | (zero placeholder)                                       | Test nullifier used by `resolve_gated_link`/`set_verifying_key`                                                                                                                                          |

1. Build and use the contract:
    - To build the Interlinked contract, update the run parameters or specify them on the command line:

      ```shell
      cd contracts/interlinked
      make build
      ```

    - Deploy / upgrade / extend TTL:

      ```shell
      make deploy
      make upgrade
      make extend_ttl
      ```

    - Shorten a URL:

      ```shell
      make shortened TEST_URL=https://inl.one
      ```

      where `TEST_URL` is the URI you want to shorten.
    - Shorten a URL with a custom code:

      ```shell
      make shortened_ext TEST_URL=https://inl.one URL_CODE=bb
      ```

    - Manage API keys:

      ```shell
      make set_api_key_v1 APIKEY_V1=<client-key> APIKEY_ACCESS=255 APIKEY_TTL=3600
      ```

    - Register a circuit's verifying key, create a ZK-gated link, and resolve it with a proof (see
      [Privacy Gateway](#privacy-gateway) and [`privacy-gateway/README.md`](privacy-gateway/README.md) for how
      `proof_a`/`proof_b`/`proof_c`/`public_inputs` are generated):

      ```shell
      make set_verifying_key VK_ID=sharmony_kyc_v1
      make create_gated_link GATED_TEST_URL=https://sharmony.world/deal-room/123 VK_ID=sharmony_kyc_v1
      make resolve_gated_link GATED_CODE_LINK=!b
      ```
