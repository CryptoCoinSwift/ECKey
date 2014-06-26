//
//  ECKeyTests.swift
//  Crypto Coin Swift
//
//  Created by Sjors Provoost on 26-06-14.
//

import XCTest
import CryptoCoin

class ECKeyTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testInitWithPrivateKey() {
        let ecKey = ECKey(privateKey: 1)
        
        XCTAssertEqual(ecKey.privateKey , 1, "Private key correct");
    }
    
    func testCreateRandom() {
        let ecKey1 = ECKey.createRandom();
        let ecKey2 = ECKey.createRandom();
        
        XCTAssertNotEqual(ecKey1.privateKey, ecKey2.privateKey, "Two random private keys can't be equal");
        
    }
    
    func testPrivateKeyHexString() {
        let ecKey = ECKey(privateKey: 0x1F)
        
        XCTAssertEqual(ecKey.privateKeyHexString , "1F", "Hex string");
        
    }
}
