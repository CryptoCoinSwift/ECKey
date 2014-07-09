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
        
        XCTAssertEqual(ecKey.privateKeyHexString , "000000000000000000000000000000000000000000000000000000000000001F", "Hex string");
        
    }
    
    func testPublicKeyHexString() {
        let privateKey = UInt256(hexStringValue: "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725")

        let publicKeyX = FFInt("50863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352", curve.field)
        let publicKeyY = FFInt("2CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6", curve.field)

        let publicKeyPoint = ECPoint(x: publicKeyX, y: publicKeyY, curve: curve)
        
        let ecKey = ECKey(privateKey: privateKey, publicKeyPoint: publicKeyPoint)
        
        XCTAssertEqual(ecKey.publicKeyHexString, "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6")
    }
    
    // Disabled because it takes too long in Debug configuration.
//    func testPublicKeyPoint() {
//
//        
//        let privateKey = UInt256(decimalStringValue: "19898843618908353587043383062236220484949425084007183071220218307100305431102")
//        let publicKeyX = FFInt(dec: "83225686012142088543596389522774768397204444195709443235253141114409346958144", curve.field)
//        let publicKeyY = FFInt(dec: "23739058578904784236915560265041168694780215705543362357495033621678991351768", curve.field)
//        
//        let publicKeyPoint = ECPoint(x: publicKeyX, y: publicKeyY, curve: curve)
//        
//        let result = ECKey(privateKey, curve).publicKeyPoint
//        
//        XCTAssertTrue(result == publicKeyPoint, result.description);
//    }
    

}
