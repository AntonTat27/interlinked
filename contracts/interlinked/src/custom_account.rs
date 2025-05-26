use crate::base64_url;
use crate::contract::LinkShortener;
use crate::contract::LinkShortenerArgs;
use crate::contract::LinkShortenerClient;
use crate::error::Error;
use crate::storage::PUBLIC_KEY;
use soroban_sdk::auth::{Context, CustomAccountInterface};
use soroban_sdk::crypto::Hash;
use soroban_sdk::{contractimpl, contracttype, Bytes, BytesN, Env, Vec};

#[contracttype]
pub struct Signature {
    pub authenticator_data: Bytes,
    pub client_data_json: Bytes,
    pub signature: BytesN<64>,
}

#[derive(serde::Deserialize)]
struct ClientDataJson<'a> {
    challenge: &'a str,
}

#[contractimpl]
impl CustomAccountInterface for LinkShortener {
    type Signature = Signature;
    type Error = Error;

    #[allow(non_snake_case)]
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signature: Signature,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        // Verify that the public key produced the signature.
        let pk = env
            .storage()
            .instance()
            .get(&PUBLIC_KEY)
            .ok_or(Error::NotInitiated)?;

        let mut payload = Bytes::new(&env);

        payload.append(&signature.authenticator_data);
        payload.extend_from_array(&env.crypto().sha256(&signature.client_data_json).to_array());
        let payload = env.crypto().sha256(&payload);

        env.crypto()
            .secp256r1_verify(&pk, &payload, &signature.signature);

        // Parse the client data JSON, extracting the base64 url encoded
        // challenge.
        let client_data_json = signature.client_data_json.to_buffer::<1024>();
        let client_data_json = client_data_json.as_slice();
        let (client_data, _): (ClientDataJson, _) =
            serde_json_core::de::from_slice(client_data_json).map_err(|_| Error::JsonParseError)?;

        // Build what the base64 url challenge is expected.
        let mut expected_challenge = *b"___________________________________________";
        base64_url::encode(&mut expected_challenge, &signature_payload.to_array());

        // Check that the challenge inside the client data JSON that was signed
        // is identical to the expected challenge.
        if client_data.challenge.as_bytes() != expected_challenge {
            return Err(Error::ClientDataJsonChallengeIncorrect);
        }

        Self::extend_ttl(env);

        Ok(())
    }
}
