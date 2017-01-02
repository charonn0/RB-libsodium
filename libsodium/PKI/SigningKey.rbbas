#tag Class
Protected Class SigningKey
Inherits libsodium.PKI.KeyPair
	#tag Method, Flags = &h1000
		Sub Constructor(PasswordData As libsodium.Password, Optional Salt As MemoryBlock, Limits As libsodium.ResourceLimits = libsodium.ResourceLimits.Interactive, HashAlgorithm As Int32 = libsodium.Password.ALG_ARGON2)
		  ' this method sometimes fails inexplicably...
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

	#tag Method, Flags = &h0
		 Shared Function DerivePublicKey(PrivateKeyData As MemoryBlock) As MemoryBlock
		  ' Given a user's private key, this method computes their public key
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  CheckSize(PrivateKeyData, crypto_sign_SECRETKEYBYTES)
		  Dim pub As New MemoryBlock(crypto_sign_PUBLICKEYBYTES)
		  
		  If crypto_sign_ed25519_sk_to_pk(pub, PrivateKeyData) = 0 Then Return pub
		  
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1000
		 Shared Function Generate(Optional SeedData As MemoryBlock) As libsodium.PKI.SigningKey
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
		Function Operator_Compare(OtherKey As libsodium.PKI.SigningKey) As Integer
		  If OtherKey Is Nil Then Return 1
		  If libsodium.StrComp(Me.PrivateKey, OtherKey.PrivateKey) Then Return 0
		  Return -1
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


End Class
#tag EndClass
