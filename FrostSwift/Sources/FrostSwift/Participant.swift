//
//  Participant.swift
//  
//
//  Created by Pacu on 26-06-2024.
//

import Foundation
import FrostSwiftFFI

/// A participant of a FROST signature scheme
public class Participant {

    let keyPackage: KeyPackage

    public init(keyPackage: KeyPackage) {
        self.keyPackage = keyPackage
    }

    public func commit() {}

    public func sign() {}

}
