ECKey
======
[CryptoCoinSwift](https://github.com/CryptoCoinSwift/CryptoCoinFramework) component for elliptic curve cryptography in Swift.

Based on [ECKey](https://github.com/cryptocoinjs/eckey/) from the CryptoCoinJS project. It depends on [ECurve](https://github.com/CryptoCoinSwift/ECurve) for the underlying elliptic curve math. A private key is a [UInt256](https://github.com/CryptoCoinSwift/UInt256). A public key is an ECurvePoint which is calculated by multiplying the private key by the base point G. 