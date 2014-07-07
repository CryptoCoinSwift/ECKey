//
//  ECKeyTests.swift
//  Crypto Coin Swift
//
//  Created by Sjors Provoost on 26-06-14.
//

import XCTest
import CryptoCoinMac
import ECurveMac
import UInt256Mac

class ECKeyTests: XCTestCase {
    
    let curve = ECurve(domain: .Secp256k1)

    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testInitWithPrivateKey() {
        let ecKey = ECKey(1, curve)
        
        XCTAssertEqual(ecKey.privateKey , 1, "Private key correct");
    }
    
    func testCreateRandom() {
        let ecKey1 = ECKey.createRandom(curve);
        let ecKey2 = ECKey.createRandom(curve);
        
        XCTAssertNotEqual(ecKey1.privateKey, ecKey2.privateKey, "Two random private keys can't be equal");
        
    }
    
    func testPrivateKeyHexString() {
        let ecKey = ECKey(0x1F, curve)
        
        XCTAssertEqual(ecKey.privateKeyHexString , "1F", "Hex string");
        
    }
    
    func testPublicKeyPoint() {

        
        let privateKey = UInt256(decimalStringValue: "19898843618908353587043383062236220484949425084007183071220218307100305431102")
        let publicKeyX = FFInt(dec: "83225686012142088543596389522774768397204444195709443235253141114409346958144", curve.field)
        let publicKeyY = FFInt(dec: "23739058578904784236915560265041168694780215705543362357495033621678991351768", curve.field)
        
        let publicKeyPoint = ECPoint(x: publicKeyX, y: publicKeyY, curve: curve)
        
        let result = ECKey(privateKey, curve).publicKeyPoint
        
        XCTAssertTrue(result == publicKeyPoint, result.description);
    }
    

}
