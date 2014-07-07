//
//  ECKey.swift
//  Crypto Coin Swift
//
//  Created by Sjors Provoost on 26-06-14.

import Foundation

import ECurveMac
import UInt256Mac

class ECKey {
    let privateKey: UInt256
    let curve: ECurve
    
    @lazy var publicKeyPoint: ECPoint = self.privateKey * self.curve.G
    
    
    var privateKeyHexString: String {
        return privateKey.toHexStringOfLength(64)
    }
    
    init(_ privateKey: UInt256, _ curve: ECurve) {
        self.privateKey = privateKey
        self.curve = curve
    }
    
    convenience init(_ privateKeyHex: String, _ curve: ECurve) {
        self.init(UInt256(hexStringValue: privateKeyHex), curve)
    }
    
    class func createRandom (curve: ECurve) -> ECKey {

        // Private key is a random 256 bit integer smaller than n.
        while(true) {
            let candidate = UInt256(arc4random_uniform(UInt32.max), arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max))
            
            if candidate < curve.n {
                return ECKey(candidate, curve)
            }
        }
    }

  
    
    
    
}