BASE_URL ?= https://base.url/
STELLAR_NETWORK ?= testnet
# GBAYDT57YWYZUWFRWBEJXHDE74USXPH36QLSYD63AKYROJUIOMPJHHQ6
# SD4YG42JMHV76CSDGVVXN5QWT6NOKXQP75ESLYBKKVF7CN2O7VXEUYSE
OWNER_SEED ?= SD4YG42JMHV76CSDGVVXN5QWT6NOKXQP75ESLYBKKVF7CN2O7VXEUYSE
CONTRACT_ADDRESS ?= CCDVXD2RA6FH6ZGNEVLD4UNR6JKADITH4HSY6GOBIVAEK7Q44WJSPWP3
PUBLIC_KEY ?= 041d1351316999a6df3e0e571dd5d37d437f19812c8ae7c3a069df435c0fee8b5a424501f14a6c13036639c9db0f889450f2e4b249b9b8be77e0d88f2611ce61b8
CREDENTIALS ?= eyJJRCI6ImpSREljSURvRU1FTEZ3Wng5ckltZzIwSGRkVT0iLCJQdWJsaWNLZXkiOiJwUUVDQXlZZ0FTRllJTEtHNDRaUUYxS05MN0R6Wmpqd1ZQWkIxQUhuWEFka3VCbG5COFUzUGJZRklsZ2cyMVpVYXBhU0ZrTVFOQWFNTWttNEdrellsNHhLYjh0elBVUVpPLzFpMVkwPSIsIkF0dGVzdGF0aW9uVHlwZSI6Im5vbmUiLCJBdXRoZW50aWNhdG9yIjp7IkFBR1VJRCI6Iisvd3dCeFZPVHN5TUMyNENCVmZYdlE9PSIsIlNpZ25Db3VudCI6MCwiQ2xvbmVXYXJuaW5nIjpmYWxzZX19
TEST_URL ?= https://test.test

build:
	stellar contract build
	stellar contract optimize --wasm .\target\wasm32-unknown-unknown\release\interlinked.wasm

install: build
	stellar contract deploy --wasm .\target\wasm32-unknown-unknown\release\interlinked.optimized.wasm \
			 --network $(STELLAR_NETWORK) --very-verbose \
			 --source-account $(OWNER_SEED) \
			 -- --base_url $(BASE_URL) --public_key $(PUBLIC_KEY) --credentials $(CREDNTIALS)

upgrade: build
	$(eval INSTALL_HASH := $(shell stellar contract install -q --network $(STELLAR_NETWORK) \
 			 --wasm .\target\wasm32-unknown-unknown\release\interlinked.optimized.wasm \
			 --source-account "$(OWNER_SEED)"))
	@echo "Install hash: $(INSTALL_HASH)"
	stellar contract invoke  --network $(STELLAR_NETWORK)  --source-account $(OWNER_SEED) \
			 --id $(CONTRACT_ADDRESS) \
 		 	 -- upgrade --new_wasm_hash $(INSTALL_HASH)

shortened:
	stellar contract invoke  --network $(STELLAR_NETWORK)  --source-account $(OWNER_SEED) \
    			 --id $(CONTRACT_ADDRESS) \
     		 	 -- shortened --url $(TEST_URL)