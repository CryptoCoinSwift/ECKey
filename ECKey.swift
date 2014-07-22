//
//  ECKey.swift
//  Crypto Coin Swift
//
//  Created by Sjors Provoost on 26-06-14.

import Foundation

import ECurveMac
import UInt256Mac

public class ECKey {
    public let privateKey: UInt256
    public let curve: ECurve
    
    public let publicKeyPoint: ECPoint
    
    
    public init(_ privateKey: UInt256, _ curve: ECurve, skipPublicKeyGeneration: Bool = false) {
        self.privateKey = privateKey
        self.curve = curve
        
        if !skipPublicKeyGeneration {
            self.publicKeyPoint = self.privateKey * self.curve.G
        } else {
            self.publicKeyPoint = curve.infinity
        }
    }
    
    public init(privateKey: UInt256, publicKeyPoint: ECPoint) {
        self.privateKey = privateKey
        self.publicKeyPoint = publicKeyPoint
        self.curve = publicKeyPoint.curve
    }
    
    public convenience init(_ privateKeyHex: String, _ curve: ECurve, skipPublicKeyGeneration: Bool = false) {
        self.init(UInt256(hexStringValue: privateKeyHex), curve, skipPublicKeyGeneration: skipPublicKeyGeneration)
    }
    
    public var privateKeyHexString: String {
        return privateKey.toHexStringOfLength(64)
    }
    
    public var publicKeyHexString: String {
        return "04" + publicKeyPoint.x!.value.toHexStringOfLength(64) + publicKeyPoint.y!.value.toHexStringOfLength(64)
    }
    
    public class func pointFromHex (hexString: String, _ curve: ECurve) -> ECPoint {
        assert(countElements(hexString) == 130, "Wrong size")
        
        let x: String = (hexString as NSString).substringWithRange(NSRange(location: 2, length: 64))
        let y: String = (hexString as NSString).substringWithRange(NSRange(location: 66, length: 64))
        
        return ECPoint(x: FFInt(x, curve.field), y: FFInt(y, curve.field), curve: curve)
        
    }
    
    public class func createRandom (curve: ECurve, skipPublicKeyGeneration: Bool = false) -> ECKey {

        // Private key is a random 256 bit integer smaller than n.
        while(true) {
            let candidate = UInt256(arc4random_uniform(UInt32.max), arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max))
            
            if candidate < curve.n {
                return ECKey(candidate, curve, skipPublicKeyGeneration: skipPublicKeyGeneration)
            }
        }
    }

  
    
    
    
}