# Soroban Multi-Tenant Link Shortener

A secure and scalable link shortening service built on Soroban smart contracts with multi-tenancy support. The project
consists of two main contracts:

## Contracts

### Multi-Tenancy Contract — private repository

- Manages tenant registration and access control
- Handles tenant-specific contract deployment
- Associates public keys with tenant identifiers
- Controls admin privileges and contract upgrades

### Interlinked Contract

- Provides custom account authentication using WebAuthn - it uses the public key credentials from the WebAuth device that stores at contract initialization. 
- Handles link shortening operations
- Manages base URL configurations per tenant
- Implements secure signature verification

## Dependencies

- soroban-sdk v22.0.6
- serde v1.0.217
- log v0.4.27
- serde-json-core v0.6.0

## Setup and Configuration

### Prerequisites

- Stellar network access (testnet/mainnet)
- Soroban CLI tools

### Building, Deployment and Usage

1. Configure environment variables in the Makefile of

| Variable            | Default Value                                                    | Description                                                 |
|---------------------|------------------------------------------------------------------|-------------------------------------------------------------|
| BASE_URL            | https://base.url/                                                | Base URL for the link shortener service                     |
| STELLAR_NETWORK     | testnet                                                          | Target Stellar network (testnet/mainnet)                    |
| WASM_HASH_SHORTENER | d3cb868c413cc5d3be4a20d22994f9d3bea024ce458bb9516553046f9dae6575 | Hash of the shortener contract WASM file, for upgrades call |
| OWNER_SEED          | SD4YG42JMHV76CSDGVVXN5QWT6NOKXQP75ESLYBKKVF7CN2O7VXEUYSE         | Secret key of the contract owner                            |
| PUBLIC_KEY          |                                                                  | public key as secp256r1 public key SEC-1 encoded            |
| CREDENTIALS         |                                                                  | public key credentials from web auth                        |
| CONTRACT_ADDRESS    | CC7WOEGYDJ4N6CG5KJTVFXCKBTUJK7Z5GNAIOBTPART2DWWTT7632P3C         | Address of the deployed contract                            | 

2. Build and use the contracts:
    - To build and Interlinked contract, you should update the run parameters or specify it in a command line the following command:
      ```shell
      cd contracts/interlinked
      make build 
      ```
    - To make a short link from an uri, you should run the following command:
       ```shell
      cd contracts/interlinked
      make shortened TEST_URL=https://inl.one
      ```  
      where:
    - _TEST_URL_ is the uri you want to shorten