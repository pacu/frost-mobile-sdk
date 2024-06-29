import XCTest
@testable import FrostSwift

public class TrustedDealerTests: XCTestCase {
    func testFrostTrustedDealerGeneratesKeys() throws {
        let configuration = try Configuration(maxSigners: 3, minSigners: 2, secret: nil)
        
        let dealer = TrustedDealerCoordinator(configuration: configuration)

        // generate keys with default identifiers
        let keys = try dealer.generateKeys()

        let message = Message(data: "i am a message".data(using: .utf8)!)

        XCTAssertEqual(keys.secretShares.count, 3)

    }

    func testFrostTrustedDealerFailsWhenLessIdentifiersAreProvided() throws {
        let configuration = try Configuration(maxSigners: 3, minSigners: 2, secret: nil)

        let dealer = TrustedDealerCoordinator(configuration: configuration)

        let identifiers: [Identifier] = [
            Identifier(identifier: "0100000000000000000000000000000000000000000000000000000000000000")!,
            Identifier(identifier: "0200000000000000000000000000000000000000000000000000000000000000")!
        ]

        // generate keys with default identifiers

        XCTAssertThrowsError(try dealer.generateKeys(with: identifiers))
    }

    func testFrostTrustedDealerFailsWhenMoreIdentifiersAreProvided() throws {
        let configuration = try Configuration(maxSigners: 3, minSigners: 2, secret: nil)

        let dealer = TrustedDealerCoordinator(configuration: configuration)

        let identifiers: [Identifier] = [
            Identifier(identifier: "0100000000000000000000000000000000000000000000000000000000000000")!,
            Identifier(identifier: "0200000000000000000000000000000000000000000000000000000000000000")!,
            Identifier(identifier: "0300000000000000000000000000000000000000000000000000000000000000")!,
            Identifier(identifier: "0400000000000000000000000000000000000000000000000000000000000000")!
        ]

        // generate keys with default identifiers
        XCTAssertThrowsError(try dealer.generateKeys(with: identifiers))
    }


    func testFrostTrustedDealerGeneratesKeysFromIdentifiers() throws {
        let configuration = try Configuration(maxSigners: 3, minSigners: 2, secret: nil)

        let dealer = TrustedDealerCoordinator(configuration: configuration)

        let identifiers: [Identifier] = [
            Identifier(identifier: "0100000000000000000000000000000000000000000000000000000000000000")!,
            Identifier(identifier: "0200000000000000000000000000000000000000000000000000000000000000")!,
            Identifier(identifier: "0300000000000000000000000000000000000000000000000000000000000000")!
        ]

        // generate keys with default identifiers
        let keys = try dealer.generateKeys(with: identifiers)

        XCTAssertEqual(keys.secretShares.count, 3)

        let expectedIdentifiers = Set(identifiers)
        let result = Set(keys.secretShares.keys)

        /// Same identifiers are returned
        XCTAssertEqual(expectedIdentifiers, result)

    }
}
