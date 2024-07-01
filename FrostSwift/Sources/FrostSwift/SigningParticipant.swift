//
//  Participant.swift
//  
//
//  Created by Pacu on 26-06-2024.
//

import Foundation
import FrostSwiftFFI

enum ParticipantError: Error {

    /// participant attempted to produce a signature share but
    /// it was missing the corresponing nonces. generate a commitment first
    case missingSigningNonces
    /// Participant attempted to produce a signature share but it was
    /// missing the corresponding key package and randomizer
    case missingRound2Config

    /// Participant is attempting to sign a randomized scheme but lacks
    /// the needed randomizer
    case missingRandomizer
}

/// This is the configuration of Round 2. This means that all participants of the
/// threshold signature round will need to share a `SigningPackage` and
/// for the case of Re-Randomized FROST, a `Randomizer`. If the different
/// participants don't use the same randomizer the signature creation will fail.
public struct Round2Configuration {
    public var signingPackage: SigningPackage
    public var randomizer: Randomizer?
}

/// A participant of a FROST signature scheme
public class SigningParticipant {
    let publicKey: PublicKeyPackage
    let keyPackage: KeyPackage
    var signingNonces: SigningNonces?
    var round2Config: Round2Configuration?

    public var identifier: Identifier { keyPackage.identifier }
    
    public init(keyPackage: KeyPackage, publicKey: PublicKeyPackage) {
        self.keyPackage = keyPackage
        self.publicKey = publicKey
    }

    public func commit() throws -> SigningCommitments {
        let commitments = try generateNoncesAndCommitments(keyPackage: keyPackage.package)
        
        let nonces = SigningNonces(nonces: commitments.nonces)
        self.signingNonces = nonces

        return SigningCommitments(commitment: commitments.commitments)
    }

    public func receive(round2Config: Round2Configuration) {
        self.round2Config = round2Config
    }

    /// produces a signature share after receiving a signing Package from the
    /// signing commitment sent to the coordinator
    /// - throws: will throw `missingSigningNonces` or `missingSigningPackage`
    /// if any of those preconditions are not met
    public func sign() throws -> SignatureShare {
        guard let nonces = signingNonces else {
            throw ParticipantError.missingSigningNonces
        }

        guard let round2Config = self.round2Config else {
            throw ParticipantError.missingRound2Config
        }

        guard let randomizer = round2Config.randomizer else {
            throw ParticipantError.missingRandomizer
        }

        let share = try FrostSwiftFFI.sign(
            signingPackage: round2Config.signingPackage.package,
            nonces: nonces.nonces,
            keyPackage: self.keyPackage.package,
            randomizer: randomizer.randomizer
        )

        return SignatureShare(share: share)
    }

}
