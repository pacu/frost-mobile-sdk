//
//  TrustedDealerSignatureIntegrationTest.swift
//  
//
//  Created by Pacu in 2024.
//
   

import XCTest
import FrostSwift
final class TrustedDealerSignatureIntegrationTest: XCTestCase {

    func testSignatureFromTrustedDealerWithNonSigningCoordinator() async throws {
        // Trusted Dealer 2 of 3
        let configuration = try Configuration(maxSigners: 3, minSigners: 2, secret: nil)

        let dealer = TrustedDealerCoordinator(configuration: configuration)

        // generate keys with default identifiers
        let keys = try dealer.generateKeys()

        // message to sign
        let message = Message(data: "i am a message".data(using: .utf8)!)

        // assert that we have the right amount of participants
        XCTAssertEqual(keys.secretShares.count, 3)

        var participants = [Identifier : SigningParticipant]()

        try keys.secretShares
            .map { try $0.value.verifyAndGetKeyPackage() }
            .map {
                SigningParticipant(
                    keyPackage: $0,
                    publicKey: keys.publicKeyPackage
                )
            }
            .forEach { p in
                participants[p.identifier] = p
            }

        let coordinator: FROSTCoordinator = try NonSigningCoordinator(
            configuration: configuration,
            publicKeyPackage: keys.publicKeyPackage,
            message: message
        )

        // we need 2 signers so we will drop the first one.
        let signingParticipants = participants.keys.dropFirst()

        // gather commitments from t participants
        // could be anyone of them
        for identifier in signingParticipants {
            // get participant
            let participant = participants[identifier]
            // participant computes a commitmetn (and a nonce for itself)
            let commitment = try participant!.commit()

            // coordinator receives the commitments 
            try await coordinator.receive(commitment: commitment)
        }

        // create signing package
        let round2Config = try await coordinator.createSigningPackage()


        // for every participan
        for identifier in signingParticipants {

            // get participant
            let participant = participants[identifier]!
            
            // send the participant the signing package
            participant.receive(round2Config: round2Config)
            // participant should create a signature (round 2)
            let signatureShare = try participant.sign()
            // coordinator should receive the signature share from the participant
            try await coordinator.receive(signatureShare: signatureShare)
        }

        // produce the signature
        let signature = try await coordinator.aggregate()

        let publicKey = keys.publicKeyPackage

        
        XCTAssertNoThrow(
            try publicKey.verify(
                message: message,
                signature: signature,
                randomizer: round2Config.randomizer!
            )
        )

    }
}
