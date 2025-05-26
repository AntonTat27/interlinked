use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    NotInitiated = 1,
    AlreadyInitiated = 2,
    ClientDataJsonChallengeIncorrect = 3,
    Secp256r1PublicKeyParse = 4,
    Secp256r1SignatureParse = 5,
    Secp256r1VerifyFailed = 6,
    JsonParseError = 7,
}
