use frost::{round1::{SigningCommitments, SigningNonces}, Error};
#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use uniffi;
use rand::thread_rng;

use crate::{coordinator::FrostSigningPackage, FrostKeyPackage, FrostSecretKeyShare, ParticipantIdentifier};
#[derive(uniffi::Record)]
pub struct FrostSigningNonces {
    pub data: Vec<u8>
}

impl FrostSigningNonces {
    pub(crate) fn to_signing_nonces(&self) -> Result<SigningNonces, Error> {
        SigningNonces::deserialize(&self.data)
    }
}

#[derive(uniffi::Record)]
pub struct FrostSigningCommitments {
    pub identifier: ParticipantIdentifier,
    pub data: Vec<u8>
}

impl FrostSigningCommitments {
    pub (crate) fn to_commitments(&self) -> Result<SigningCommitments, Error> {
        SigningCommitments::deserialize(&self.data)
    }
}
#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum Round1Error {
    #[error("Provided Key Package is invalid.")]
    InvalidKeyPackage,
    #[error("Nonce could not be serialized.")]
    NonceSerializationError,
    #[error("Commitment could not be serialized.")]
    CommitmentSerializationError,
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum Round2Error {
    #[error("Provided Key Package is invalid.")]
    InvalidKeyPackage,
    #[error("Nonce could not be serialized.")]
    NonceSerializationError,
    #[error("Commitment could not be serialized.")]
    CommitmentSerializationError,
    #[error("Could not deserialize Signing Package.")]
    SigningPackageDeserializationError,
    #[error("Failed to sign message with error: {message:?}")]
    SigningFailed {
        message: String
    }
}

#[derive(uniffi::Record)]
pub struct FirstRoundCommitment {
    pub nonces: FrostSigningNonces,
    pub commitments: FrostSigningCommitments,
}

#[uniffi::export]
pub fn generate_nonces_and_commitments(secret_share: FrostSecretKeyShare) -> Result<FirstRoundCommitment, Round1Error> {

    let mut rng = thread_rng();

    let secret_share = secret_share
        .to_secret_share()
        .map_err(|_| Round1Error::InvalidKeyPackage)?;

    let _ = secret_share.verify()
        .map_err(|_| Round1Error::InvalidKeyPackage)?;

    let signing_share = secret_share.signing_share();
    let (nonces, commitments) = frost::round1::commit(signing_share, & mut rng);

    Ok(
        FirstRoundCommitment {
            nonces: FrostSigningNonces {
                data: nonces.serialize()
                    .map_err(|_| Round1Error::NonceSerializationError)?
            },
            commitments: FrostSigningCommitments {
                identifier: ParticipantIdentifier::from_identifier(*secret_share.identifier())
                    .map_err(|_| Round1Error::InvalidKeyPackage)?,
                data: commitments.serialize()
                    .map_err(|_| Round1Error::CommitmentSerializationError)?
            }
        }
    )
}


#[derive(uniffi::Record)]
pub struct FrostSignatureShare {
    data: Vec<u8>
}

#[uniffi::export]
pub fn sign(signing_package: FrostSigningPackage, nonces: FrostSigningNonces, key_package: FrostKeyPackage) -> Result<FrostSignatureShare, Round2Error> {
    let signing_package = signing_package.to_signing_package()
        .map_err(|_| Round2Error::SigningPackageDeserializationError)?;

    let nonces = nonces.to_signing_nonces()
        .map_err(|_| Round2Error::NonceSerializationError)?;

    let key_package = key_package.into_key_package()
        .map_err(|_| Round2Error::InvalidKeyPackage)?;

    frost::round2::sign(&signing_package, &nonces, &key_package)
        .map_err(|e|
            Round2Error::SigningFailed{
                message: e.to_string()
            }
        )
        .map(|share| FrostSignatureShare { data: share.serialize().to_vec() } )
}