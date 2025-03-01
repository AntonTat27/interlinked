BASE_URL ?= https://base.url/
STELLAR_NETWORK ?= testnet
# GBAYDT57YWYZUWFRWBEJXHDE74USXPH36QLSYD63AKYROJUIOMPJHHQ6
# SD4YG42JMHV76CSDGVVXN5QWT6NOKXQP75ESLYBKKVF7CN2O7VXEUYSE
OWNER_SEED ?= SD4YG42JMHV76CSDGVVXN5QWT6NOKXQP75ESLYBKKVF7CN2O7VXEUYSE
CONTRACT_ADDRESS ?= CCDVXD2RA6FH6ZGNEVLD4UNR6JKADITH4HSY6GOBIVAEK7Q44WJSPWP3

build:
	stellar contract build
	stellar contract optimize --wasm .\target\wasm32-unknown-unknown\release\interlinked.wasm

install: build
	stellar contract deploy --wasm .\target\wasm32-unknown-unknown\release\interlinked.optimized.wasm \
			 --network $(STELLAR_NETWORK) --very-verbose \
			 --source-account $(OWNER_SEED) \
			 -- --base_url $(BASE_URL)

upgrade: build
	$(eval INSTALL_HASH := $(shell stellar contract install -q --network $(STELLAR_NETWORK) \
 			 --wasm .\target\wasm32-unknown-unknown\release\interlinked.optimized.wasm \
			 --source-account "$(OWNER_SEED)"))
	@echo "Install hash: $(INSTALL_HASH)"
	stellar contract invoke  --network $(STELLAR_NETWORK)  --source-account $(OWNER_SEED) \
			 --id $(CONTRACT_ADDRESS) \
 		 	 -- upgrade --new_wasm_hash $(INSTALL_HASH)

test:
	stellar contract invoke  --network $(STELLAR_NETWORK)  --source-account $(OWNER_SEED) \
    			 --id $(CONTRACT_ADDRESS) \
     		 	 -- shortened --merchant m1 --url https://test.test