//
//  Coordinator.swift
//
//
//  Created by Pacu on 27-06-2024.
//

import Foundation
import FrostSwiftFFI

public class SigningCoordinator {
    public let configuration: Configuration
    public let publicKeyPackage: PublicKeyPackage

    var signingPackage: FrostSigningPackage?
    var signatureShares: [SignatureShare] = []

    init(configuration: Configuration, publicKeyPackage: PublicKeyPackage) {
        self.configuration = configuration
        self.publicKeyPackage = publicKeyPackage
    }

    public func aggregate() {}
    
}
