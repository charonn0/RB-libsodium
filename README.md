## Introduction
[libsodium](https://github.com/jedisct1/libsodium) is a cross-platform fork of the [NaCl](http://nacl.cr.yp.to/) cryptographic library. It provides secret-key and public-key encryption ([XSalsa20](https://en.wikipedia.org/wiki/Salsa20)), message authentication ([Poly1305](https://en.wikipedia.org/wiki/Poly1305)), digital signatures ([Ed25519](https://en.wikipedia.org/wiki/EdDSA)), key exchange ([X25519](https://en.wikipedia.org/wiki/Curve25519)), generic hashing ([BLAKE2b](https://en.wikipedia.org/wiki/BLAKE_(hash_function)), SHA256, SHA512), password hashing and key derivation ([scrypt](https://en.wikipedia.org/wiki/Scrypt) or [Argon2i](https://en.wikipedia.org/wiki/Argon2)), in addition to facilities for guarded memory allocations and constant-time string comparisons. 

**RB-libsodium** is a libsodium [binding](http://en.wikipedia.org/wiki/Language_binding) for Realbasic and Xojo ("classic" framework) projects. It is designed and tested using REALstudio 2011r4.3 on Windows 7. Library binaries for [a number of platforms](https://download.libsodium.org/libsodium/releases/) are available, or can built from source. 

## Example
This example generates and validates a password hash that is suitable to be stored in a database ([more examples](https://github.com/charonn0/RB-libsodium/wiki#examples)):
```vbnet
  Dim pw As libsodium.Password = "seekrit"
  Dim hash As String = pw.GenerateHash()
  If Not pw.VerifyHash(hash) Then MsgBox("Bad password!")
```

## Hilights
* [Password hashing](https://github.com/charonn0/RB-libsodium/wiki/libsodium.Password.GenerateHash) and [Password-based key derivation (PBKDF2)](https://github.com/charonn0/RB-libsodium/wiki/libsodium.Password.DeriveKey) using either Argon2 or scrypt
* [Secret-key](https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI) and [public-key](https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI) cryptography
* Diffie-Hellman key exchange ([X25519](https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SharedSecret))
* Secret-key [message authentication](https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.GenerateMAC)
* Public-key [message signatures](https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SignData)
* Fast generic or keyed hashing using [BLAKE2b](https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHash), [SHA512](https://github.com/charonn0/RB-libsodium/wiki/libsodium.SHA512), or [SHA256](https://github.com/charonn0/RB-libsodium/wiki/libsodium.SHA256)
* [Secured memory](https://github.com/charonn0/RB-libsodium/wiki/libsodium.SecureMemoryblock) allocations
* Import and export keys, messages, hashes, etc. with optional password protection.

## Synopsis
RB-libsodium is designed to make it as hard as possible to write bad crypto code. For example signing keys can't be used to perform encryption, so methods that need a signing key will require an instance of the [SigningKey](https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningKey) class as a parameter; attempting to pass an [EncryptionKey](https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey) will generate a compiler error. 

libsodium uses state-of-the-art cryptographic primitives and algorithms based on [elliptic curves](https://en.wikipedia.org/wiki/Elliptic_curve_cryptography) ("ECC"). ECC provides comparable security to older systems based on prime factorization, such as RSA, but with much smaller key sizes. For example, a 224-bit (28 byte) ECC key provides a level of security that is comparable to a 2,048-bit (256 byte) RSA key. For comparison, [NIST recommends](https://www.keylength.com/en/4/) a RSA key size of at least 3,072 bits to ensure security through the year 2030.

## How to incorporate libsodium into your Realbasic/Xojo project
### Import the libsodium module
1. Download the RB-libsodium project either in [ZIP archive format](https://github.com/charonn0/RB-libsodium/archive/master.zip) or by cloning the repository with your Git client.
2. Open the RB-libsodium project in REALstudio or Xojo. Open your project in a separate window.
3. Copy the libsodium module into your project and save.

### Ensure the libsodium shared library is installed
libsodium is not ordinarily installed by default on most operating systems, you will need to ship necessary DLL/SO/DyLibs with your application. You can use pre-built binaries available [here](https://download.libsodium.org/libsodium/releases/), or you can [build them yourself from source](https://github.com/jedisct1/libsodium). 

RB-libsodium will raise a PlatformNotSupportedException when used if all required DLLs/SOs/DyLibs are not available at runtime. 

## Examples
* [Secure memory](https://github.com/charonn0/RB-libsodium/wiki/Secure-Memory-Example)
* [Password hashing](https://github.com/charonn0/RB-libsodium/wiki/Password-Example#generate-a-hash)
* [Generic hashing](https://github.com/charonn0/RB-libsodium/wiki/Generic-Hash-Example)
* PKI
  * Encryption
    * [Generate a key pair](https://github.com/charonn0/RB-libsodium/wiki/PKI-Encryption-Examples#generate-a-new-random-encryption-key)
    * [Derive a key pair from a password](https://github.com/charonn0/RB-libsodium/wiki/PKI-Encryption-Examples#generate-a-new-encryption-key-from-a-password-pbkdf2)
    * [Encrypt data](https://github.com/charonn0/RB-libsodium/wiki/PKI-Encryption-Examples#encrypt-data)
    * [Decrypt data](https://github.com/charonn0/RB-libsodium/wiki/PKI-Encryption-Examples#decrypt-data)
  * Digital signatures
    * [Generate a key pair](https://github.com/charonn0/RB-libsodium/wiki/PKI-Digital-Signature-Examples#generate-a-new-random-key-pair)
    * [Derive a key pair from a password](https://github.com/charonn0/RB-libsodium/wiki/PKI-Digital-Signature-Examples#generate-a-new-encryption-key-from-a-password-pbkdf2)
    * [Sign data](https://github.com/charonn0/RB-libsodium/wiki/PKI-Digital-Signature-Examples#sign-data)
    * [Verify data](https://github.com/charonn0/RB-libsodium/wiki/PKI-Digital-Signature-Examples#verify-data)
* SKI
  * Encryption
    * [Generate a key](https://github.com/charonn0/RB-libsodium/wiki/SKI-Encryption-Examples#generate-a-new-random-key)
    * [Derive a key from a password](https://github.com/charonn0/RB-libsodium/wiki/SKI-Encryption-Examples#generate-a-new-key-from-a-password-pbkdf2)
    * [Encrypt data](https://github.com/charonn0/RB-libsodium/wiki/SKI-Encryption-Examples#encrypt-data)
    * [Decrypt data](https://github.com/charonn0/RB-libsodium/wiki/SKI-Encryption-Examples#decrypt-data)
  * Message authentication
	* [Generate a MAC](https://github.com/charonn0/RB-libsodium/wiki/SKI-Encryption-Examples#generate-and-validate-a-message-authentication-code)
    * [Verify a MAC](https://github.com/charonn0/RB-libsodium/wiki/SKI-Encryption-Examples#generate-and-validate-a-message-authentication-code)
