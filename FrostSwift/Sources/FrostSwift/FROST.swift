import FrostSwiftFFI

enum FrostError: Error {
    case invalidConfiguration
}

enum FrostSwift {

    static func frost() -> String {
        "❄️"
    }
}


public struct PublicKeyPackage {
    private let package: FrostPublicKeyPackage

    init(package: FrostPublicKeyPackage) {
        self.package = package
    }

    public var verifyingKey: VerifyingKey { VerifyingKey(key: package.verifyingKey) }

    /// All the participants involved in this KeyPackage
    public var participants: [Identifier] {
        package.verifyingShares.keys.map{ Identifier(identifier: $0.data) }
    }

    public func verifyingShare(for participant: Identifier) -> VerifyingShare? {
        guard let share = package.verifyingShares[participant.id]
        else { return nil }

        return VerifyingShare(share: share)
    }
}

public struct Identifier: Hashable {
    let id: ParticipantIdentifier

    public var asString: String { id.data }


    public init(identifier: String) {
        self.id = ParticipantIdentifier(data: identifier)
    }
}

public struct VerifyingShare {
    private let share: String

    init(share: String) {
        self.share = share
    }

    public var asString: String { share }
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
        Identifier(identifier: self.package.identifier)
    }
}

public struct SecretShare {
    let share: FrostSecretKeyShare

    init(share: FrostSecretKeyShare) {
        self.share = share
    }
}

