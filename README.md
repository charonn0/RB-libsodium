##Introduction
[libsodium](https://github.com/jedisct1/libsodium) is a cross-platform fork of the [NaCl](http://nacl.cr.yp.to/) cryptographic library. It provides secret-key and public-key encryption ([XSalsa20](https://en.wikipedia.org/wiki/Salsa20)), message authentication ([Poly1305](https://en.wikipedia.org/wiki/Poly1305)), digital signatures ([Ed25519](https://en.wikipedia.org/wiki/EdDSA)), key exchange ([X25519](https://en.wikipedia.org/wiki/Curve25519)), generic hashing ([BLAKE2b](https://en.wikipedia.org/wiki/BLAKE_(hash_function))) and password hashing ([scrypt](https://en.wikipedia.org/wiki/Scrypt) or [Argon2](https://en.wikipedia.org/wiki/Argon2)), in addition to facilities for secure memory allocations and constant-time string comparisons. 

**RB-libsodium** is a libsodium [binding](http://en.wikipedia.org/wiki/Language_binding) for Realbasic and Xojo ("classic" framework) projects. It is designed and tested using REALstudio 2011r4.3 on Windows 7. Library binaries for [a number of platforms](https://download.libsodium.org/libsodium/releases/) are available, or can built from source. 

##Example
This example generates a private key, derives the corresponding public key, for both a sender and recipient; and encrypts and decrypts a message:

```vbnet
  ' generate a new private key for the sender
  Dim senderprivkey As MemoryBlock = libsodium.PKI.RandomKey()
  ' derive the sender's public key
  Dim senderkeys As libsodium.PKI.EncryptionKey = libsodium.PKI.EncryptionKey.Derive(senderprivkey) 
  
  ' generate a new private key for the recipient
  Dim recipientprivkey As MemoryBlock = libsodium.PKI.RandomKey()
  ' derive the recipient's public key
  Dim recipientkeys As libsodium.PKI.EncryptionKey = libsodium.PKI.EncryptionKey.Derive(recipientprivkey)
  
  ' the nonce is not secret but shouldn't be reused
  Dim nonce As MemoryBlock = libsodium.PKI.RandomNonce()
  
  ' encrypt the message
  Dim cleartext As String = "Attack at dawn."
  Dim crypttext As String = libsodium.PKI.EncryptData(cleartext, recipientkeys.PublicKey, senderkeys, nonce)
  
  ' decrypt the message
  Dim decrypted As String = libsodium.PKI.DecryptData(crypttext, senderkeys.PublicKey, recipientkeys, nonce)
```
##Hilights
* Guarded heap allocations
* Mark memory as non-swapable
* Securely hash passwords using hard hash functions
* Secret-key and public-key cryptography
* Key exchange
* Secret-key message authentication 
* Public-key message signatures

##Synopsis

***
It is strongly recommended that you familiarize yourself with [libsodium](http://doc.libsodium.org/), as this documentation is for the wrapper itself and not the underlying library. 
***

The wrapper is divided into three main parts: secret-key (SKI), public-key (PKI), and non-cryptographic (everything else).


##How to incorporate libsodium into your Realbasic/Xojo project
###Import the libsodium module
1. Download the RB-libsodium project either in [ZIP archive format](https://github.com/charonn0/RB-libsodium/archive/master.zip) or by cloning the repository with your Git client.
2. Open the RB-libsodium project in REALstudio or Xojo. Open your project in a separate window.
3. Copy the libsodium module into your project and save.

###Ensure the libsodium shared library is installed
libsodium is not ordinarily installed by default on most operating systems, you will need to ship necessary DLL/SO/DyLibs with your application. You can use pre-built binaries available [here](https://download.libsodium.org/libsodium/releases/), or you can [build them yourself from source](https://github.com/jedisct1/libsodium). 

RB-libsodium will raise a PlatformNotSupportedException when used if all required DLLs/SOs/DyLibs are not available at runtime. 

##Examples
* [Secure memory](https://github.com/charonn0/RB-libcURL/wiki/Secure-Memory-Example)
