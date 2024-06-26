//
//  TrustedDealer.swift
//
//
//  Created by Pacu on 26-6-2024.
//

import Foundation
import FrostSwiftFFI

/// Configuration of the FROST Threshold signature scheme.
/// - Note: when configuring a trusted dealer coordinator, if the secret is not provided one will be generated
public struct Configuration {
    let maxSigners: UInt16
    let minSigners: UInt16
    let secret: Data?

    init(maxSigners: UInt16, minSigners: UInt16, secret: Data?) throws {
        guard minSigners < maxSigners
        else {
            throw FrostError.invalidConfiguration
        }

        self.maxSigners = maxSigners
        self.minSigners = minSigners
        self.secret = secret
    }

}

/// Represents a Trusted Dealer Key Generation Coordinator.
/// Only use this Key dealership scheme when you can undeniably trust the dealer
/// - Note: `SecretShare`s must be sent to participants through encrypted and
/// authenticated communication channels!.
public struct TrustedDealerCoordinator {

    public struct KeyGeneration {
        public let publicKeyPackage: PublicKeyPackage
        public let secretShares: [Identifier : SecretShare]

        init(publicKeyPackage: PublicKeyPackage, secretShares: [Identifier : SecretShare]) {
            self.publicKeyPackage = publicKeyPackage
            self.secretShares = secretShares
        }
    }

    public let configuration: Configuration

    public init(configuration: Configuration) {
        self.configuration = configuration
    }

    public func generateKeys() throws -> KeyGeneration {
        let keys = try trustedDealerKeygenFrom(configuration: configuration.intoFFIConfiguration())
        
        return keys.toKeyGeneration()
    }

    public func generateKeys(with identifiers: [Identifier]) throws -> KeyGeneration  {
        guard identifiers.count == configuration.maxSigners else {
            throw FrostError.invalidConfiguration
        }

        let keys = try trustedDealerKeygenWithIdentifiers(configuration: self.configuration.intoFFIConfiguration(), participants: ParticipantList(identifiers: identifiers.map({ $0.toParticipantIdentifier()})))

        return keys.toKeyGeneration()
    }
}



