//
//  FFIConversion.swift
//  
//
//  Created by Pacu on 26-06-2024.
//

import Foundation
import FrostSwiftFFI


extension Configuration {
    func intoFFIConfiguration() -> FrostSwiftFFI.Configuration {
        FrostSwiftFFI.Configuration(minSigners: self.minSigners, maxSigners: self.maxSigners, secret: self.secret ?? Data())
    }
}

extension ParticipantIdentifier {
    func toIdentifier() -> Identifier {
        Identifier(identifier: self.data)
    }
}

extension Identifier {
    func toParticipantIdentifier() -> ParticipantIdentifier {
        self.id
    }
}
extension TrustedKeyGeneration {
    func toKeyGeneration() -> TrustedDealerCoordinator.KeyGeneration {
        
        var keys = [Identifier : SecretShare]()

        self.secretShares.forEach { keys[$0.key.toIdentifier()] = SecretShare(share: $0.value)}

        return TrustedDealerCoordinator.KeyGeneration(publicKeyPackage: PublicKeyPackage(package: self.publicKeyPackage), secretShares: keys)
    }
}
