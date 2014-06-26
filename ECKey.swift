//
//  ECKey.swift
//  Crypto Coin Swift
//
//  Created by Sjors Provoost on 26-06-14.

import Foundation

class ECKey {
    let privateKey: UInt256
        
    var privateKeyHexString: String {
        return privateKey.toHexString
    }
    
    init(privateKey: UInt256) {
        self.privateKey = privateKey
    }
    
    class func createRandom () -> ECKey {
        return ECKey(privateKey: UInt256(mostSignificantOf8UInt32First: [arc4random_uniform(UInt32.max), arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max),arc4random_uniform(UInt32.max)]))
    }

}
