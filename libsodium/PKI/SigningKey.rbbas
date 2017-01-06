#tag Class
Protected Class SigningKey
Inherits libsodium.PKI.KeyPair
	#tag Method, Flags = &h1000
		Sub Constructor(PasswordData As libsodium.Password, Optional Salt As MemoryBlock, Limits As libsodium.ResourceLimits = libsodium.ResourceLimits.Interactive, HashAlgorithm As Int32 = libsodium.Password.ALG_ARGON2)
		  ' this method sometimes fails inexplicably...
		  ' Compute a SigningKey from a hash of the password
		  If Salt <> Nil Then CheckSize(Salt, crypto_pwhash_SALTBYTES) Else Salt = libsodium.SKI.SecretKey.RandomSalt
		  Dim seckey As MemoryBlock = PasswordData.DeriveKey(crypto_sign_SECRETKEYBYTES, Salt, Limits, HashAlgorithm)
		  Dim pubkey As MemoryBlock = DerivePublicKey(seckey)
		  // Calling the overridden superclass constructor.
		  Me.Constructor(seckey, pubkey)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1001
		Protected Sub Constructor(PrivateKeyData As MemoryBlock)
		  CheckSize(PrivateKeyData, crypto_sign_SECRETKEYBYTES)
		  Dim pub As New MemoryBlock(crypto_sign_PUBLICKEYBYTES)
		  If crypto_scalarmult_base(pub, PrivateKeyData) = 0 Then Raise New SodiumException(ERR_COMPUTATION_FAILED)
		  Me.Constructor(PrivateKeyData, pub)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1001
		Protected Sub Constructor(PrivateKeyData As MemoryBlock, PublicKeyData As MemoryBlock)
		  CheckSize(PrivateKeyData, crypto_sign_SECRETKEYBYTES)
		  CheckSize(PublicKeyData, crypto_sign_PUBLICKEYBYTES)
		  
		  // Calling the overridden superclass constructor.
		  // Constructor(PrivateKeyData As MemoryBlock, PublicKeyData As MemoryBlock) -- From KeyPair
		  Super.Constructor(PrivateKeyData, PublicKeyData)
		  Me.Lock()
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Derive(PrivateKeyData As MemoryBlock) As libsodium.PKI.SigningKey
		  ' This method extracts the public key from the PrivateKeyData, and returns a SigningKey containing both.
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Return New SigningKey(PrivateKeyData, DerivePublicKey(PrivateKeyData))
		  
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Shared Function DerivePublicKey(PrivateKeyData As MemoryBlock) As MemoryBlock
		  ' Given a user's private key, this method computes their public key
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  CheckSize(PrivateKeyData, crypto_sign_SECRETKEYBYTES)
		  Dim pub As New MemoryBlock(crypto_sign_PUBLICKEYBYTES)
		  
		  If crypto_sign_ed25519_sk_to_pk(pub, PrivateKeyData) = 0 Then Return pub
		  
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Export() As MemoryBlock
		  Dim data As New MemoryBlock(0)
		  Dim bs As New BinaryStream(data)
		  
		  bs.Write("-----BEGIN ED25519 PUBLIC KEY BLOCK-----" + EndOfLine.Windows)
		  bs.Write(EndOfLine.Windows)
		  bs.Write(EncodeBase64(Me.PublicKey) + EndOfLine.Windows)
		  bs.Write("-----END ED25519 PUBLIC KEY BLOCK-----" + EndOfLine.Windows)
		  
		  bs.Write("-----BEGIN ED25519 PRIVATE KEY BLOCK-----" + EndOfLine.Windows)
		  bs.Write(EndOfLine.Windows)
		  bs.Write(EncodeBase64(Me.PrivateKey) + EndOfLine.Windows)
		  bs.Write("-----END ED25519 PRIVATE KEY BLOCK-----" + EndOfLine.Windows)
		  
		  bs.Close
		  Return data
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1000
		 Shared Function Generate(Optional SeedData As MemoryBlock) As libsodium.PKI.SigningKey
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
		 Shared Function Import(ExportedKey As MemoryBlock) As libsodium.PKI.SigningKey
		  Dim lines() As String = SplitB(ExportedKey, EndOfLine.Windows)
		  If lines(0) <> "-----BEGIN ED25519 PUBLIC KEY BLOCK-----" Then Return Nil
		  Dim pk As New MemoryBlock(0)
		  Dim bs As New BinaryStream(pk)
		  Dim i As Integer
		  For i = 1 To UBound(lines)
		    If lines(i) <> "-----END ED25519 PUBLIC KEY BLOCK-----" Then
		      bs.Write(lines(i) + EndOfLine.Windows)
		    Else
		      Exit For
		    End If
		  Next
		  bs.Close
		  i = i + 1
		  If lines(i) <> "-----BEGIN ED25519 PRIVATE KEY BLOCK-----" Then Return Nil
		  i = i + 1
		  Dim sk As New MemoryBlock(0)
		  bs = New BinaryStream(sk)
		  For i = i To UBound(lines)
		    If lines(i) <> "-----END ED25519 PRIVATE KEY BLOCK-----" Then
		      bs.Write(lines(i) + EndOfLine.Windows)
		    Else
		      Exit For
		    End If
		  Next
		  bs.Close
		  
		  Return Derive(DecodeBase64(sk))
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As libsodium.PKI.SigningKey) As Integer
		  If OtherKey Is Nil Then Return 1
		  If libsodium.StrComp(Me.PrivateKey, OtherKey.PrivateKey) Then Return 0
		  Return -1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomSeed() As MemoryBlock
		  ' Returns random bytes that are suitable to be used as a seed for SigningKey.Generate
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Return RandomBytes(crypto_sign_SEEDBYTES)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Seed() As MemoryBlock
		  ' This method extracts the seed from the private key. This is either a random seed 
		  ' or the one passed to SigningKey.Generate.
		  
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
		
		
		To generate a brand new signing key use the libsodium.PKI.SigningKey.Generate() method, optionally
		passing in some seed data.
		
		     Dim sigk As libsodium.PKI.SigningKey = libsodium.PKI.SigningKey.Generate()
		
		To derive SigningKey key from a password string use the Constructor method. Derivation requires a random salt, 
		which you should get from the SecretKey.RandomSalt() shared method:
		
		     Dim pw As libsodium.Password = "seekrit"
		     Dim salt As MemoryBlock = libsodium.SKI.SecretKey.RandomSalt()
		     Dim sigk As New libsodium.PKI.SigningKey(pw, salt)
		
	#tag EndNote
End Class
#tag EndClass
