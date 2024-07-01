package frost_uniffi_sdk

import "testing"

func TestTrustedDealerRedPallas(t *testing.T) {
	secret := []byte{}

	// define the threshold config
	secretConfig := Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Secret:     secret,
	}

	// message to be signed. (This will not be known beforehand in
	// a real test)
	message := Message{
		Data: []byte("i am a message"),
	}

	// Start the trusted dealer key generation with the given config
	keygen, err := TrustedDealerKeygenFrom(secretConfig)
	if err != nil {
		t.Fatalf("Failed to generate keygen: %v", err)
	}

	// this is the first public key (not re-randomized)
	publicKey := keygen.PublicKeyPackage
	// these are the secret key shares that each participant will use
	shares := keygen.SecretShares

	keyPackages := make(map[ParticipantIdentifier]FrostKeyPackage)
	for identifier, value := range shares {
		// this verifies the share and generates a key package for each
		// participant
		keyPackage, err := VerifyAndGetKeyPackageFrom(value)
		if err != nil {
			t.Fatalf("Failed to get key package: %v", err)
		}
		keyPackages[identifier] = keyPackage
	}

	if len(shares) != 3 {
		t.Fatalf("Expected 3 shares, got %d", len(shares))
	}

	if len(publicKey.VerifyingShares) != 3 {
		t.Fatalf("Expected 3 verifying shares, got %d", len(publicKey.VerifyingShares))
	}

	nonces := make(map[ParticipantIdentifier]FrostSigningNonces)
	var commitments []FrostSigningCommitments

	for participant, secretShare := range shares {

		keyPackage, err := VerifyAndGetKeyPackageFrom(secretShare)
		// generates a nonce and a commitment to be used (round 1)
		firstRoundCommitment, err := GenerateNoncesAndCommitments(keyPackage)
		if err != nil {
			t.Fatalf("Failed to generate nonces and commitments: %v", err)
		}
		nonces[participant] = firstRoundCommitment.Nonces
		commitments = append(commitments, firstRoundCommitment.Commitments)
	}

	// create a signing package using the message to be signed and the
	// the commitments from the first round.
	signingPackage, err := NewSigningPackage(message, commitments)
	if err != nil {
		t.Fatalf("Failed to create signing package: %v", err)
	}

	randomizedParams, err := RandomizedParamsFromPublicKeyAndSigningPackage(publicKey, signingPackage)

	if err != nil {
		t.Fatalf("Failed to derive randomized params from public key and signing package: %v", err)
	}
	randomizer, err := RandomizerFromParams(randomizedParams)

	if err != nil {
		t.Fatalf("Failed to create randomizer from randomized params: %v", err)
	}

	var signatureShares []FrostSignatureShare

	// now, each participant has to generate a signaature from it's own nonce,
	// key package, and the signing package.
	for participant, keyPackage := range keyPackages {
		signatureShare, err := Sign(signingPackage, nonces[participant], keyPackage, randomizer)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}
		signatureShares = append(signatureShares, signatureShare)
	}

	// the coordinator will receive the signatures produced by the t participants
	// and aggregate them. This will produce a signature that will be verified
	signature, err := Aggregate(signingPackage, signatureShares, publicKey, randomizer)
	if err != nil {
		t.Fatalf("Failed to aggregate signature: %v", err)
	}

	// verify the signature
	if err := VerifyRandomizedSignature(randomizer, message, signature, publicKey); err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
}
