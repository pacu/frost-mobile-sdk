//
//  Error.swift
//
//
//  Created by Pacu in 2024.
//    
   

import Foundation
import FrostSwiftFFI

public enum FrostError: Error {

    case invalidConfiguration
    case invalidSignature
    case malformedIdentifier
    case otherError(FrostSwiftFFI.FrostError)
}


