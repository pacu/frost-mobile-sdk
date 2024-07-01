//
//  ModelTests.swift
//  
//
//  Created by Pacu 28-06-2024
//

import XCTest
import FrostSwift
final class ModelTests: XCTestCase {
    func testConfigurationThrows(){
        XCTAssertThrowsError(try Configuration(maxSigners: 3, minSigners: 4, secret: nil))
    }

    func testConfigurationWorks() {
        XCTAssertNoThrow(try Configuration(maxSigners: 4, minSigners: 3, secret: nil))
    }

    func testIdentifierSerializationFromString() {
        XCTAssertNotNil(Identifier(identifier: "0100000000000000000000000000000000000000000000000000000000000000"))
        
    }

    func testIdentifierSerializationFromScalar() throws{
        XCTAssertNotNil(Identifier(with: 1))

        let expectedId = "0100000000000000000000000000000000000000000000000000000000000000"


        let stringIdentifier = try Identifier(with: 1)?.toString()

        XCTAssertEqual(expectedId, stringIdentifier)

    }
}
