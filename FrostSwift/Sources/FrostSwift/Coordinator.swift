//
//  Coordinator.swift
//
//
//  Created by Pacu on 27-06-2024.
//

import Foundation
import FrostSwiftFFI
enum FROSTCoordinatorError: Error {

    case alreadyReceivedCommitmentFromIdentifier(Identifier)
    case alreadyReceivedSignatureShareFromIdentifier(Identifier)
    case incorrectNumberOfCommitments(min: UInt16, max: UInt16, found: UInt16)
    case signingPackageAlreadyCreated
    case signingPackageMissing
    // mapped from FFI
    case failedToCreateSigningPackage
    case invalidSigningCommitment
    case identifierDeserializationError
    case signingPackageSerializationError
    case signatureShareDeserializationError
    case publicKeyPackageDeserializationError
    case signatureShareAggregationFailed(message: String)
    case invalidRandomizer

    /// some error we don't have mapped
    case otherError(CoordinationError)

    init(coordinationError: CoordinationError) {
        switch coordinationError {
        case .FailedToCreateSigningPackage:
            self = .failedToCreateSigningPackage
        case .InvalidSigningCommitment:
            self = .invalidSigningCommitment
        case .IdentifierDeserializationError:
            self = .identifierDeserializationError
        case .SigningPackageSerializationError:
            self = .signingPackageSerializationError
        case .SignatureShareDeserializationError:
            self = .signatureShareDeserializationError
        case .PublicKeyPackageDeserializationError:
            self = .publicKeyPackageDeserializationError
        case .SignatureShareAggregationFailed(message: let message):
            self = .signatureShareAggregationFailed(message: message)
        case .InvalidRandomizer:
            self = .invalidRandomizer
        }
    }
}

/// Protocol that defines the minimum functionality of a FROST signature
/// scheme Coordinator. A coordinator can be part of the signature or not.  For your
/// convenience, ``NonSigningCoordinator`` and ``SigningCoordinator``
/// implementations are provided.
/// - Important: Fallback because of misbehaving participants are not considered
/// within this protocol. Implementors must define their own strategies to deal with such
/// scenarios.
/// - Note: This protocol is bound to actors because it is assumed that several
/// participants may try to interact with it concurrently.
public protocol FROSTCoordinator: Actor {
    /// configuration of the FROST threshold scheme
    var configuration: Configuration { get }
    /// public key tha represent this signature scheme
    var publicKeyPackage: PublicKeyPackage { get }
    /// message to be signed by the _t_ participants
    var message: Message { get }
    /// this is the configuration of Round 2.
    var round2Config: Round2Configuration? { get }
    /// receives a signing commitment from a given participant
    /// - parameter commitment: the SigningCommitment from signature participant
    /// - throws: should throw ``FROSTCoordinatorError.alreadyReceivedCommitmentFromIdentifier`` when
    /// receiving a commitment from an Identifier that was received already independently from whether
    /// it is the same or a different one.
    func receive(commitment: SigningCommitments) throws
    /// Creates a ``Round2Configuration`` struct with a ``SigningPackage`` and
    /// ``Randomizer`` for the case that Re-Randomized FROST is used.
    /// - throws: ``FROSTCoordinatorError.signingPackageAlreadyCreated`` if this function was
    /// called already or ``FROSTCoordinatorError.incorrectNumberOfCommitments``
    /// when the number of commitments gathered is less or more than the specified by the ``Configuration``
    func createSigningPackage() throws -> Round2Configuration
    /// Receives a ``SignatureShare`` from a ``SigningParticipant``.
    /// - throws: ``FROSTCoordinatorError.alreadyReceivedSignatureShareFromIdentifier``
    /// when the same participant sends the same share repeatedly
    func receive(signatureShare: SignatureShare) throws
    /// Aggregates all shares and creates the FROST ``Signature``
    /// - throws: several things can go wrong here. 🥶
    func aggregate() throws -> Signature
    /// Verify a ``Signature`` with the ``PublicKeyPackage`` of this coordinator.
    func verify(signature: Signature) throws
}


/// A signature scheme coordinator that does not participate in the signature scheme
public actor NonSigningCoordinator: FROSTCoordinator {
    public let configuration: Configuration
    public let publicKeyPackage: PublicKeyPackage
    public let message: Message
    public var round2Config: Round2Configuration?
    var commitments: [Identifier : SigningCommitments] = [:]
    var signatureShares: [Identifier : SignatureShare] = [:]

    public init(configuration: Configuration, publicKeyPackage: PublicKeyPackage, message: Message) throws {
        self.configuration = configuration
        self.publicKeyPackage = publicKeyPackage
        self.message = message
    }

    public func receive(commitment: SigningCommitments) throws {
        // TODO: validate that the commitment belongs to a known identifier
        guard commitments[commitment.identifier] == nil else {
            throw FROSTCoordinatorError.alreadyReceivedCommitmentFromIdentifier(commitment.identifier)
        }

        self.commitments[commitment.identifier] = commitment
    }

    public func createSigningPackage() throws -> Round2Configuration {
        guard self.round2Config?.signingPackage == nil else {
            throw FROSTCoordinatorError.signingPackageAlreadyCreated
        }

        try validateNumberOfCommitments()

        let package = SigningPackage(
            package: try newSigningPackage(
                message: self.message,
                commitments: self.commitments.values.map { $0.commitment }
            )
        )

        let randomizedParams = try RandomizedParams(
            publicKey: self.publicKeyPackage,
            signingPackage: package
        )

        let randomizer = try randomizedParams.randomizer()

        let config = Round2Configuration(signingPackage: package, randomizer: randomizer)
        self.round2Config = config

        return config
    }

    /// receives the signature share from a partipicant
    public func receive(signatureShare: SignatureShare) throws {
        // TODO: validate that the commitment belongs to a known identifier
        guard self.signatureShares[signatureShare.identifier] == nil else {
            throw FROSTCoordinatorError.alreadyReceivedSignatureShareFromIdentifier(signatureShare.identifier)
        }

        self.signatureShares[signatureShare.identifier] = signatureShare
    }

    public func aggregate() throws -> Signature {
        try validateNumberOfCommitments()
        let round2config = try round2ConfigPresent()

        guard let randomizer = round2config.randomizer?.randomizer else {
            throw FROSTCoordinatorError.invalidRandomizer
        }

        let signature = try FrostSwiftFFI.aggregate(
            signingPackage: round2config.signingPackage.package,
            signatureShares: self.signatureShares.values.map { $0.share },
            pubkeyPackage: self.publicKeyPackage.package,
            randomizer: randomizer
        )

        return Signature(signature: signature)
    }

    public func verify(signature: Signature) throws {
        throw FrostError.invalidSignature
    }

    func round2ConfigPresent() throws -> Round2Configuration {
        guard let config = self.round2Config else {
            throw FROSTCoordinatorError.signingPackageMissing
        }

        return config
    }

    func validateNumberOfCommitments() throws {
        guard   commitments.count >= configuration.minSigners &&
                commitments.count <= configuration.maxSigners
        else {
            throw FROSTCoordinatorError.incorrectNumberOfCommitments(
                    min: configuration.minSigners,
                    max: configuration.maxSigners,
                    found: UInt16(commitments.count)
                )
        }
    }
}

/// A Coordinator that also participates in the signature production.
public actor SigningCoordinator: FROSTCoordinator {
    public let configuration: Configuration
    public let publicKeyPackage: PublicKeyPackage
    public let message: Message
    let keyPackage: KeyPackage
    public var round2Config: Round2Configuration?
    var commitments: [Identifier : SigningCommitments] = [:]
    var signatureShares: [Identifier : SignatureShare] = [:]

    public init(configuration: Configuration, publicKeyPackage: PublicKeyPackage, keyPackage: KeyPackage, message: Message) throws {
        self.configuration = configuration
        self.publicKeyPackage = publicKeyPackage
        self.message = message
        self.keyPackage = keyPackage
    }

    public func receive(commitment: SigningCommitments) throws {
        throw FrostError.malformedIdentifier
    }

    public func createSigningPackage() throws -> Round2Configuration {
        throw FROSTCoordinatorError.signingPackageAlreadyCreated
//        guard signingPackage == nil else {
//            throw FROSTCoordinatorError.signingPackageAlreadyCreated
//        }
//
//        let package = newSigningPackage(message: self.message, commitments: <#T##[FrostSigningCommitments]#>)
//        self.signingPackage = SigningPackage(package: <#T##FrostSigningPackage#>)
    }

    public func receive(signatureShare: SignatureShare) throws {
        throw FrostError.malformedIdentifier
    }

    public func aggregate() throws -> Signature {
        throw FrostError.invalidConfiguration
    }

    public func verify(signature: Signature) throws {
        throw FrostError.invalidSignature
    }
}
