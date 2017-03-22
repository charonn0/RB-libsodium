#tag Class
Protected Class SigningKey
Inherits libsodium.PKI.KeyPair
	#tag Method, Flags = &h1000
		Sub Constructor(PasswordData As libsodium.Password, Optional Salt As MemoryBlock, Limits As libsodium.ResourceLimits = libsodium.ResourceLimits.Interactive, HashAlgorithm As Int32 = libsodium.Password.ALG_ARGON2)
		  ' Generates a key pair by deriving it from a salted hash of the password. The operation is 
		  ' deterministic, such that calling this method twice with the same Password, Salt, and Limits 
		  ' parameters will produce the same output both times.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningKey.Constructor
		  
		  If Salt = Nil Then Salt = PasswordData.RandomSalt(HashAlgorithm)
		  Me.Constructor(PasswordData.DeriveKey(crypto_sign_SECRETKEYBYTES, Salt, Limits, HashAlgorithm))
		  mPasswdSalt = Salt
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1001
		Protected Sub Constructor(PrivateKeyData As MemoryBlock)
		  ' Given a user's private key, this method computes their public key
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  CheckSize(PrivateKeyData, crypto_sign_SECRETKEYBYTES)
		  
		  Dim pub As New MemoryBlock(crypto_sign_PUBLICKEYBYTES)
		  If crypto_sign_ed25519_sk_to_pk(pub, PrivateKeyData) = 0 Then
		    Me.Constructor(PrivateKeyData, pub)
		  Else
		    Raise New SodiumException(ERR_COMPUTATION_FAILED)
		  End If
		  
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1001
		Protected Sub Constructor(PrivateKeyData As MemoryBlock, PublicKeyData As MemoryBlock)
		  CheckSize(PrivateKeyData, crypto_sign_SECRETKEYBYTES)
		  CheckSize(PublicKeyData, crypto_sign_PUBLICKEYBYTES)
		  
		  // Calling the overridden superclass constructor.
		  // Constructor(PrivateKeyData As MemoryBlock, PublicKeyData As MemoryBlock) -- From KeyPair
		  Super.Constructor(PrivateKeyData, PublicKeyData)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Derive(PrivateKeyData As MemoryBlock) As libsodium.PKI.SigningKey
		  ' Given a user's private key, this method generates a SigningKey pair
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningKey.Derive
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Return New SigningKey(PrivateKeyData)
		  
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function DeriveChild(Nonce As MemoryBlock) As libsodium.PKI.SigningKey
		  Dim fk As ForeignKey = LeftB(Me.PrivateKey, 32) ' truncate
		  Dim stream As New KeyStream(fk)
		  Dim sk As MemoryBlock = stream.DeriveKey(crypto_sign_SECRETKEYBYTES, Nonce)
		  If sk <> Nil Then Return New SigningKey(sk)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Export(SaveTo As FolderItem, Optional Passwd As libsodium.Password, OverWrite As Boolean = False) As Boolean
		  ' Exports the SigningKey in a format that is understood by SigningKey.Import(FolderItem)
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningKey.Export
		  
		  Try
		    Dim bs As BinaryStream = BinaryStream.Create(SaveTo, OverWrite)
		    bs.Write(Me.Export(Passwd))
		    bs.Close
		  Catch Err As IOException
		    Return False
		  End Try
		  Return True
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Export(Optional Passwd As libsodium.Password) As MemoryBlock
		  ' Exports the SigningKey in a format that is understood by SigningKey.Import
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningKey.Export
		  
		  Dim data As New MemoryBlock(0)
		  Dim bs As New BinaryStream(data)
		  bs.Write(libsodium.Exporting.Export(Me.PrivateKey, libsodium.Exporting.ExportableType.SignPrivate, Passwd))
		  bs.Close
		  Return data
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1000
		 Shared Function Generate(Optional SeedData As MemoryBlock) As libsodium.PKI.SigningKey
		  ' This method randomly generates a SigningKey pair, optionally using the specified seed.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningKey.Generate
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Dim pub As New MemoryBlock(crypto_sign_PUBLICKEYBYTES)
		  Dim priv As New MemoryBlock(crypto_sign_SECRETKEYBYTES)
		  If SeedData = Nil Then
		    If crypto_sign_keypair(pub, priv) = -1 Then Return Nil
		  Else
		    CheckSize(SeedData, crypto_sign_SEEDBYTES)
		    If crypto_sign_seed_keypair(pub, priv, SeedData) = -1 Then Return Nil
		  End If
		  Return New SigningKey(priv, pub)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Import(ExportedKey As FolderItem, Optional Passwd As libsodium.Password) As libsodium.PKI.SigningKey
		  ' Import a SigningKey that was exported using SigningKey.Export(FolderItem)
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningKey.Import
		  
		  Dim bs As BinaryStream = BinaryStream.Open(ExportedKey)
		  Dim keydata As MemoryBlock = bs.Read(bs.Length)
		  bs.Close
		  Return Import(keydata, Passwd)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Import(ExportedKey As MemoryBlock, Optional Passwd As libsodium.Password) As libsodium.PKI.SigningKey
		  ' Import a SigningKey that was exported using SigningKey.Export
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningKey.Import
		  
		  Dim sk As MemoryBlock = libsodium.Exporting.Import(ExportedKey, Passwd)
		  If sk <> Nil Then Return Derive(sk)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As libsodium.PKI.SigningKey) As Int32
		  ' This method overloads the comparison operator (=) allowing direct comparisons between
		  ' instances of SigningKey. The comparison operation itself is a constant-time binary
		  ' comparison of the private key halves of both key pairs; the public halves are not compared.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningKey.Operator_Compare
		  
		  If OtherKey Is Nil Then Return 1
		  Return Super.Operator_Compare(OtherKey)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomSeed() As MemoryBlock
		  ' Returns unpredictable bytes that are suitable to be used as a seed for SigningKey.Generate
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningKey.RandomSeed
		  
		  Return RandomBytes(crypto_sign_SEEDBYTES)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Seed() As MemoryBlock
		  ' This method extracts the seed from the private key. This is either a random seed
		  ' or the one passed to SigningKey.Generate.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningKey.Seed
		  
		  Dim seed As New MemoryBlock(crypto_sign_SEEDBYTES)
		  If crypto_sign_ed25519_sk_to_seed(seed, Me.PrivateKey) = 0 Then Return seed
		End Function
	#tag EndMethod


	#tag Note, Name = Usage
		This class contains a key pair for use with public key signatures. 
		
		You may use a SigningKey with these utility methods:
		
		  * libsodium.PKI.SignData: Sign a message.
		  * libsodium.PKI.VerifyData: Verify a signed message.
		
		Signing is done using the Ed25519 digital signature algorithm.
		
		
		To generate a brand new signing key use the .Generate() method, optionally
		passing in some seed data.
		
		     Dim sigk As libsodium.PKI.SigningKey
		     sigk = sigk.Generate()
		
		To derive SigningKey key from a password use the Constructor method. 
		Derivation requires a random salt, which you should get from the 
		Password.RandomSalt() shared method:
		
		     Dim pw As libsodium.Password = "seekrit"
		     Dim salt As MemoryBlock = pw.RandomSalt()
		     Dim sigk As New libsodium.PKI.SigningKey(pw, salt)
	#tag EndNote


End Class
#tag EndClass
