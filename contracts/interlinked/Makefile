BASE_URL ?= https://base.url/
STELLAR_NETWORK ?= testnet
# GBAYDT57YWYZUWFRWBEJXHDE74USXPH36QLSYD63AKYROJUIOMPJHHQ6
# SD4YG42JMHV76CSDGVVXN5QWT6NOKXQP75ESLYBKKVF7CN2O7VXEUYSE
OWNER_SEED ?= SD4YG42JMHV76CSDGVVXN5QWT6NOKXQP75ESLYBKKVF7CN2O7VXEUYSE
ADMIN_ADDRESS ?= CBKR4W7L7C5H6SCBK2RZ2LBSKYFDVTGMJ5UAEGWL2PWQ7KLWDNK6GRVL
CONTRACT_ADDRESS ?= CCBGT2AD2GW5UCNFVP6WA46LK6CDDEUSFQBWF6EKEX5T63TA3L2RLPND
PUBLIC_KEY ?= 041d1351316999a6df3e0e571dd5d37d437f19812c8ae7c3a069df435c0fee8b5a424501f14a6c13036639c9db0f889450f2e4b249b9b8be77e0d88f2611ce61b8
CREDENTIALS ?= eyJJRCI6ImpSREljSURvRU1FTEZ3Wng5ckltZzIwSGRkVT0iLCJQdWJsaWNLZXkiOiJwUUVDQXlZZ0FTRllJTEtHNDRaUUYxS05MN0R6Wmpqd1ZQWkIxQUhuWEFka3VCbG5COFUzUGJZRklsZ2cyMVpVYXBhU0ZrTVFOQWFNTWttNEdrellsNHhLYjh0elBVUVpPLzFpMVkwPSIsIkF0dGVzdGF0aW9uVHlwZSI6Im5vbmUiLCJBdXRoZW50aWNhdG9yIjp7IkFBR1VJRCI6Iisvd3dCeFZPVHN5TUMyNENCVmZYdlE9PSIsIlNpZ25Db3VudCI6MCwiQ2xvbmVXYXJuaW5nIjpmYWxzZX19
TEST_URL ?= https://test.test
URL_CODE ?= bb
APIKEY_ACCESS ?= 255
APIKEY_TTL ?= 3600

GATED_TEST_URL ?= https://sharmony.world/deal-room/123
GATED_CONTENT_TYPE ?= deal_room
CIRCUIT_ID ?= link_access
VK_ID ?= sharmony_kyc_v1
POLICY_HASH ?= 0000000000000000000000000000000000000000000000000000000000000000
GATED_CODE_LINK ?= !b

# placeholder zero-value test vectors â€” correctly SIZED for compile/call-plumbing testing only.
# These will fail pairing_check (or trap on point validation) since they are not real proof
# output. Real values must come from an actual Noir/Circom proof + the matching trusted-setup VK.
ZERO_G1 ?= 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
ZERO_G2 ?= 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
NULLIFIER ?= 0000000000000000000000000000000000000000000000000000000000000000

WASM_PATH := .\target\wasm32v1-none\release\interlinked.wasm
WASM_PATH_OPTIMIZED := .\target\wasm32v1-none\release\interlinked.optimized.wasm

build:
	stellar contract build

optimize: build
	stellar contract optimize --wasm $(WASM_PATH)

install: optimize
	$(eval INSTALL_HASH := $(shell stellar contract upload --network $(STELLAR_NETWORK) \
     			 --wasm $(WASM_PATH_OPTIMIZED) \
    			 --source-account "$(OWNER_SEED)"))
	@echo "Install hash: $(INSTALL_HASH)"

deploy: optimize
	stellar contract deploy --wasm $(WASM_PATH_OPTIMIZED) \
			 --network $(STELLAR_NETWORK) --very-verbose \
			 --source-account $(OWNER_SEED) \
			 -- --base_url $(BASE_URL) --admin $(ADMIN_ADDRESS)

upgrade: optimize
	$(eval INSTALL_HASH := $(shell stellar contract upload -q --network $(STELLAR_NETWORK) \
 			 --wasm $(WASM_PATH_OPTIMIZED) \
			 --source-account "$(OWNER_SEED)"))
	@echo "Install hash: $(INSTALL_HASH)"
	stellar contract invoke  --network $(STELLAR_NETWORK)  --source-account $(OWNER_SEED) \
			 --id $(CONTRACT_ADDRESS) \
 		 	 -- upgrade --new_wasm_hash '"$(INSTALL_HASH)"'
extend_ttl:
	stellar contract invoke  --network $(STELLAR_NETWORK)  --source-account $(OWNER_SEED) \
			 --id $(CONTRACT_ADDRESS) --send=yes \
 		 	 -- extend_ttl

shortened:
	stellar contract invoke  --network $(STELLAR_NETWORK)  --source-account $(OWNER_SEED) \
    			 --id $(CONTRACT_ADDRESS) \
     		 	 -- shortened --url $(TEST_URL)

shortened_ext:
	stellar contract invoke  --network $(STELLAR_NETWORK)  --source-account $(OWNER_SEED) \
    			 --id $(CONTRACT_ADDRESS) \
     		 	 -- shortened_ext --url $(TEST_URL) --url_code $(URL_CODE)

set_api_key_v1:
	stellar contract invoke  --network $(STELLAR_NETWORK)  --source-account $(OWNER_SEED) \
    			 --id $(CONTRACT_ADDRESS) \
     		 	 -- set_api_key_v1 --key $(APIKEY_V1) --access $(APIKEY_ACCESS) --ttl_ms $(APIKEY_TTL)

set_verifying_key:
	stellar contract invoke  --network $(STELLAR_NETWORK)  --source-account $(OWNER_SEED) \
    			 --id $(CONTRACT_ADDRESS) \
     		 	 -- set_verifying_key --vk_id $(VK_ID) \
     		 	 --alpha_g1 $(ZERO_G1) --beta_g2 $(ZERO_G2) --gamma_g2 $(ZERO_G2) --delta_g2 $(ZERO_G2) \
     		 	 --ic '["$(ZERO_G1)"]'

create_gated_link:
	stellar contract invoke  --network $(STELLAR_NETWORK)  --source-account $(OWNER_SEED) \
    			 --id $(CONTRACT_ADDRESS) \
     		 	 -- create_gated_link --url $(GATED_TEST_URL) --content_type $(GATED_CONTENT_TYPE) \
     		 	 --circuit_id $(CIRCUIT_ID) --policy_hash $(POLICY_HASH) --vk_id $(VK_ID)

resolve_gated_link:
	stellar contract invoke  --network $(STELLAR_NETWORK)  --source-account $(OWNER_SEED) \
    			 --id $(CONTRACT_ADDRESS) \
     		 	 -- resolve_gated_link --code_link $(GATED_CODE_LINK) \
     		 	 --proof_a $(ZERO_G1) --proof_b $(ZERO_G2) --proof_c $(ZERO_G1) \
     		 	 --public_inputs '["$(NULLIFIER)"]' --nullifier $(NULLIFIER)

test:
	stellar contract invoke  --network $(STELLAR_NETWORK)  --source-account $(OWNER_SEED) \
    			 --id $(CONTRACT_ADDRESS) \
     		 	 -- init_disposable_link --salt 68656c6c6f74 --attempts 3

test1:
	stellar contract invoke  --network $(STELLAR_NETWORK)  --source-account $(OWNER_SEED) \
        			 --id $(CONTRACT_ADDRESS) \
         		 	 -- disposable_link --code_link ~f --url test_link

test2:
	stellar contract invoke  --network $(STELLAR_NETWORK)  --source-account $(OWNER_SEED) \
        			 --id $(CONTRACT_ADDRESS) \
         		 	 -- resolve_disposable_link --code_link ~f --salt 68656c6c6f74

test3:
	stellar contract invoke  --network $(STELLAR_NETWORK)  --source-account $(OWNER_SEED) \
        			 --id $(CONTRACT_ADDRESS) \
         		 	 -- temporary_link --url $(TEST_URL) --duration 10000

test4:
	stellar contract invoke  --network $(STELLAR_NETWORK) --send=yes  --source-account $(OWNER_SEED) \
        			 --id $(CONTRACT_ADDRESS) \
         		 	 -- extend_link_ttl --code_link ~i --duration 40000
