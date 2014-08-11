//
//  ECKeyTests.swift
//  Crypto Coin Swift
//
//  Created by Sjors Provoost on 26-06-14.
//

import XCTest
import CryptoCoin
import ECurve
import UInt256

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
        let ecKey1 = ECKey.createRandom(curve, skipPublicKeyGeneration: true);
        let ecKey2 = ECKey.createRandom(curve, skipPublicKeyGeneration: true);
        
        XCTAssertNotEqual(ecKey1.privateKey, ecKey2.privateKey, "Two random private keys can't be equal");
        
    }
    
    func testPrivateKeyHexString() {
        let ecKey = ECKey(0x1F, curve, skipPublicKeyGeneration: true)
        
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
    
    func testSign() { // Signature verification is a bit slow
        let privateKey = UInt256(hexStringValue: "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725")
        
        let publicKeyX = FFInt("50863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352", curve.field)
        let publicKeyY = FFInt("2CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6", curve.field)
        
        let publicKeyPoint = ECPoint(x: publicKeyX, y: publicKeyY, curve: curve)

        let ecKey = ECKey(privateKey: privateKey, publicKeyPoint: publicKeyPoint)

        // Not checking the signature
        let digest: UInt256 = 0x32
        let (r,s) = ecKey.sign(digest)
        let (r2,s2) = ecKey.sign(digest)

        XCTAssertNotEqual(r,r2, "Not a nonce")
        XCTAssertNotEqual(s,s2, "No two signatures can be identical")

        // Uncomment to print r and s values:
//        XCTAssertEqual(r.toHexString + " " + s.toHexString, "", "Not a real test.");

        
        // Valid signature (checked with Ruby ecdsa gem): 61CCAE675AE09AF5D3B1831D1604B6A578DCBB3493DC04A7077E4BD194CBBB6C AE1DA0CA5D73FEE85885F31BEF5894F2D2CB3E8392163E20127368E33534B53D
    
        XCTAssertTrue(ECKey.verifySignature(digest, r: r, s: s, publicKey: publicKeyPoint), "Verification")
        
        XCTAssertFalse(ECKey.verifySignature(digest, r: r, s: s + 1, publicKey: publicKeyPoint), "Verification")
    
        XCTAssertFalse(ECKey.verifySignature(digest, r: r, s: s + 1, publicKey: publicKeyPoint.double), "Verification")
        
        let r3 = UInt256(hexStringValue: "61CCAE675AE09AF5D3B1831D1604B6A578DCBB3493DC04A7077E4BD194CBBB6C")
        
        let s3 = UInt256(hexStringValue: "AE1DA0CA5D73FEE85885F31BEF5894F2D2CB3E8392163E20127368E33534B53D")
        
        XCTAssertTrue(ECKey.verifySignature(digest, r: r3, s: s3, publicKey: publicKeyPoint), "Verification")

        
    }

}
