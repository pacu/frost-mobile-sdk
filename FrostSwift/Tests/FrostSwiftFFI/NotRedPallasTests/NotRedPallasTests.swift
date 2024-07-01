//
//  NotRedPallasTests.swift
//
//
//  Created by Pacu on 23-05-2024.
//

import Foundation
import XCTest
@testable import FrostSwiftFFI

class NotRedPallasTests: XCTestCase {
    func ignore_testTrustedDealerFromConfigWithSecret() throws {
        let secret: [UInt8] = [
            123, 28, 51, 211, 245, 41, 29, 133, 222, 102, 72, 51, 190, 177, 173, 70, 159, 127, 182, 2,
            90, 14, 199, 139, 58, 121, 12, 110, 19, 169, 131, 4,
        ]

        let secretConfig = Configuration(minSigners: 2, maxSigners: 3, secret: Data(secret))

        let message = Message(data: "i am a message".data(using: .utf8)!)

        let keygen = try trustedDealerKeygenFrom(configuration: secretConfig)

        let publicKey = keygen.publicKeyPackage
        let shares = keygen.secretShares

        // get key packages for participants
        let keyPackages = try shares.map { (identifier, value) in
            let keyPackage = try verifyAndGetKeyPackageFrom(secretShare: value)

            return (identifier, keyPackage)
        }

        XCTAssertEqual(shares.count, 3)
        XCTAssertEqual(publicKey.verifyingShares.count,3)

        // Participant Round 1

        var nonces = [ParticipantIdentifier: FrostSigningNonces]()
        var commitments = [FrostSigningCommitments]()

        for (participant, secretShare) in shares {

            let keyPackage = try verifyAndGetKeyPackageFrom(secretShare: secretShare)
            let firstRoundCommitment = try generateNoncesAndCommitments(keyPackage: keyPackage)

            nonces[participant] = firstRoundCommitment.nonces
            commitments.append(firstRoundCommitment.commitments)
        }

        // coordinator gathers all signing commitments and creates signing package

        let signingPackage = try newSigningPackage(message: message, commitments: commitments)

        // Participant round 2. These people need to sign!
        // here each participant will sign the message with their own nonces and the signing
        // package provided by the coordinator

//        let signatureShares = try keyPackages.map { participant, keyPackage in
//            try sign(signingPackage: signingPackage, nonces: nonces[participant]!, keyPackage: keyPackage)
//        }

        // Aggregators will aggregate: Coordinator gathers all the stuff and produces
        // a signature...

//        let signature = try aggregate(signingPackage: signingPackage, signatureShares: signatureShares, pubkeyPackage: publicKey)

        // a signature we can all agree on

//        XCTAssertNoThrow(try verifySignature(message: message, signature: signature, pubkey: publicKey))
    }
}
