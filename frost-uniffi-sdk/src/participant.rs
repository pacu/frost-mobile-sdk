use frost_core as frost;

use frost::{
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Ciphersuite, Error, Identifier,
};

#[cfg(feature = "redpallas")]
type E = reddsa::frost::redpallas::PallasBlake2b512;
#[cfg(not(feature = "redpallas"))]
type E = frost_ed25519::Ed25519Sha512;

use rand::thread_rng;
use uniffi;

use crate::{FrostKeyPackage, ParticipantIdentifier};

#[cfg(not(feature = "redpallas"))]
use crate::{coordinator::FrostSigningPackage, FrostKeyPackage};

#[derive(uniffi::Record, Clone)]
pub struct FrostSigningNonces {
    pub data: Vec<u8>,
}

impl FrostSigningNonces {
    pub(super) fn to_signing_nonces<C: Ciphersuite>(&self) -> Result<SigningNonces<C>, Error<C>> {
        SigningNonces::deserialize(&self.data)
    }

    pub fn from_nonces<C: Ciphersuite>(
        nonces: SigningNonces<C>,
    ) -> Result<FrostSigningNonces, Error<C>> {
        let data = nonces.serialize()?;
        Ok(FrostSigningNonces { data })
    }
}

#[derive(uniffi::Record)]
pub struct FrostSigningCommitments {
    pub identifier: ParticipantIdentifier,
    pub data: Vec<u8>,
}

impl FrostSigningCommitments {
    pub(crate) fn to_commitments<C: Ciphersuite>(&self) -> Result<SigningCommitments<C>, Error<C>> {
        SigningCommitments::deserialize(&self.data)
    }

    pub fn with_identifier_and_commitments<C: Ciphersuite>(
        identifier: Identifier<C>,
        commitments: SigningCommitments<C>,
    ) -> Result<FrostSigningCommitments, Error<C>> {
        Ok(FrostSigningCommitments {
            identifier: ParticipantIdentifier::from_identifier(identifier)?,
            data: commitments.serialize()?,
        })
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
    SigningFailed { message: String },
    #[cfg(feature = "redpallas")]
    #[error("Invalid Randomizer.")]
    InvalidRandomizer,
}

#[derive(uniffi::Record)]
pub struct FirstRoundCommitment {
    pub nonces: FrostSigningNonces,
    pub commitments: FrostSigningCommitments,
}

#[uniffi::export]
pub fn generate_nonces_and_commitments(
    key_package: FrostKeyPackage,
) -> Result<FirstRoundCommitment, Round1Error> {
    let mut rng = thread_rng();

    let key_package = key_package.into_key_package::<E>()
        .map_err(|_| Round1Error::InvalidKeyPackage)?;

    let signing_share = key_package.signing_share();
    let (nonces, commitments) = frost::round1::commit(signing_share, &mut rng);

    Ok(FirstRoundCommitment {
        nonces: FrostSigningNonces::from_nonces(nonces)
            .map_err(|_| Round1Error::NonceSerializationError)?,
        commitments: FrostSigningCommitments::with_identifier_and_commitments(
            *key_package.identifier(),
            commitments,
        )
        .map_err(|_| Round1Error::CommitmentSerializationError)?,
    })
}

#[derive(uniffi::Record)]
pub struct FrostSignatureShare {
    pub identifier: ParticipantIdentifier,
    pub data: Vec<u8>,
}

impl FrostSignatureShare {
    pub fn to_signature_share<C: Ciphersuite>(&self) -> Result<SignatureShare<E>, Error<E>> {
        let bytes: [u8; 32] = self.data[0..32]
            .try_into()
            .map_err(|_| Error::DeserializationError)?;

        // TODO: Do not define the underlying curve inside the function
        SignatureShare::<E>::deserialize(bytes)
    }

    pub fn from_signature_share<C: Ciphersuite>(
        identifier: Identifier<C>,
        share: SignatureShare<C>,
    ) -> Result<FrostSignatureShare, Error<C>> {
        Ok(FrostSignatureShare {
            identifier: ParticipantIdentifier::from_identifier(identifier)?,
            data: share.serialize().as_ref().to_vec(),
        })
    }
}

#[cfg(not(feature = "redpallas"))]
#[uniffi::export]
pub fn sign(
    signing_package: FrostSigningPackage,
    nonces: FrostSigningNonces,
    key_package: FrostKeyPackage,
) -> Result<FrostSignatureShare, Round2Error> {
    let signing_package = signing_package
        .to_signing_package::<E>()
        .map_err(|_| Round2Error::SigningPackageDeserializationError)?;

    let nonces = nonces
        .to_signing_nonces()
        .map_err(|_| Round2Error::NonceSerializationError)?;

    let key_package = key_package
        .into_key_package()
        .map_err(|_| Round2Error::InvalidKeyPackage)?;

    let identifier = *key_package.identifier();

    let share = frost::round2::sign(&signing_package, &nonces, &key_package).map_err(|e| {
        Round2Error::SigningFailed {
            message: e.to_string(),
        }
    })?;

    FrostSignatureShare::from_signature_share(identifier, share).map_err(|e| {
        Round2Error::SigningFailed {
            message: e.to_string(),
        }
    })
}
