import FrostSwiftFFI
import Foundation

enum FrostError: Error {
    case invalidConfiguration
    case malformedIdentifier
}

enum FrostSwift {

    static func frost() -> String {
        "❄️"
    }
}

public typealias Message = FrostSwiftFFI.Message

public struct PublicKeyPackage {
    let package: FrostPublicKeyPackage

    init(package: FrostPublicKeyPackage) {
        self.package = package
    }

    public var verifyingKey: VerifyingKey { VerifyingKey(key: package.verifyingKey) }

    /// All the participants involved in this KeyPackage
    public var participants: [Identifier] {
        package.verifyingShares.keys.map{ $0.toIdentifier() }
    }

    public func verifyingShare(for participant: Identifier) -> VerifyingShare? {
        guard let share = package.verifyingShares[participant.id]
        else { return nil }

        return VerifyingShare(share: share)
    }

    public func verify(message: Message, signature: Signature, randomizer: Randomizer?) throws {

        if let randomizer = randomizer {
            try verifyRandomizedSignature(randomizer: randomizer.randomizer, message: message, signature: signature.signature, pubkey: self.package)
        }

    }
}

public struct Identifier: Hashable {
    let id: ParticipantIdentifier

    init(participant: ParticipantIdentifier) {
        self.id = participant
    }

    public init?(with scalar: UInt16) {
        if let id = try? identifierFromUint16(unsignedUint: scalar) {
            self.id = id
        } else {
            return nil
        }
    }
    
    /// constructs a JSON-formatted string from the given string to create an identifier
    public init?(identifier: String) {
        if let id = try? identifierFromString(string: identifier) {
            self.id = id
        } else {
            return nil
        }
    }

    public init?(jsonString: String) {
        if let id = identifierFromJsonString(string: jsonString) {
            self.id = id
        } else {
            return nil
        }
    }

    public func toString() throws -> String {
        do {
            let json = try JSONDecoder().decode(String.self, from: id.data.data(using: .utf8) ?? Data())

            return json
        } catch {
            throw FrostError.malformedIdentifier
        }
    }
}

public struct VerifyingShare {
    private let share: String

    init(share: String) {
        self.share = share
    }

    public var asString: String { share }
}

public struct RandomizedParams {
    let params: FrostSwiftFFI.FrostRandomizedParams


    init(params: FrostSwiftFFI.FrostRandomizedParams) {
        self.params = params
    }

    public init(publicKey: PublicKeyPackage, signingPackage: SigningPackage) throws {
        self.params = try randomizedParamsFromPublicKeyAndSigningPackage(
            publicKey: publicKey.package,
            signingPackage: signingPackage.package
        )
    }

    func randomizer() throws -> Randomizer {
        Randomizer(
            randomizer: try FrostSwiftFFI.randomizerFromParams(
                randomizedParams: params
            )
        )
    }
}

public struct Randomizer {
    let randomizer: FrostRandomizer

    init(randomizer: FrostRandomizer) {
        self.randomizer = randomizer
    }
}

public struct VerifyingKey {
    private let key: String

    init(key: String) {
        self.key = key
    }

    public var asString: String { key }

}

public struct KeyPackage {
    private let package: FrostKeyPackage

    init(package: FrostKeyPackage) {
        self.package = package
    }

    public var identifier: Identifier {
        self.package.identifier.toIdentifier()
    }
}

public struct SecretShare {
    let share: FrostSecretKeyShare

    init(share: FrostSecretKeyShare) {
        self.share = share
    }
}

/// Commitments produced by signature participants for a current or
/// a future signature scheme. `Coordinator` can request participants
/// to send their commitments beforehand to produce
public struct SigningCommitments {
    let commitment: FrostSigningCommitments

    public var identifier: Identifier {
        commitment.identifier.toIdentifier()
    }

    init(commitment: FrostSigningCommitments) {
        self.commitment = commitment
    }
}

/// Signature share produced by a given participant of the signature scheme
/// and sent to the `Coordinator` to then aggregate the t signature shares
/// and produce a `Signature`.
/// The `Identifier` tells the coordinator who produced this share.
/// - Note: `SignatureShare` should be sent through an
/// authenticated and encrypted channel.
public struct SignatureShare: Equatable {
    let share: FrostSignatureShare

    var identifier: Identifier {
        share.identifier.toIdentifier()
    }

    init(share: FrostSignatureShare) {
        self.share = share
    }
}

/// Signing Package created by the coordinator who sends it to
/// the t participants in the current signature scheme.
/// - Note: `SigningPackage` should be sent through an
/// authenticated and encrypted channel.
public struct SigningPackage: Equatable {
    let package: FrostSigningPackage

    init(package: FrostSigningPackage) {
        self.package = package
    }
}
/// Signature produced by aggregating the `SignatureShare`s of the
/// different
public struct Signature: Equatable, Hashable {
    let signature: FrostSignature

    public var data: Data { signature.data }
}

