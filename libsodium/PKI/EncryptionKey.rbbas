#tag Class
Protected Class EncryptionKey
Inherits libsodium.PKI.KeyPair
	#tag Method, Flags = &h1000
		Sub Constructor(PasswordData As libsodium.Password, Optional Salt As MemoryBlock, Limits As libsodium.ResourceLimits = libsodium.ResourceLimits.Interactive)
		  ' Compute an EncryptionKey from a hash of the password
		  If Salt <> Nil Then CheckSize(Salt, crypto_pwhash_SALTBYTES) Else Salt = PasswordData.RandomSalt
		  Dim seckey As MemoryBlock = PasswordData.DeriveKey(crypto_box_SECRETKEYBYTES, Salt, Limits, libsodium.Password.ALG_ARGON2)
		  Dim pubkey As MemoryBlock = libsodium.PKI.EncryptionKey.DerivePublicKey(seckey)
		  Me.Constructor(seckey, pubkey)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1001
		Protected Sub Constructor(PrivateKeyData As MemoryBlock, PublicKeyData As MemoryBlock)
		  CheckSize(PrivateKeyData, crypto_box_SECRETKEYBYTES)
		  CheckSize(PublicKeyData, crypto_box_PUBLICKEYBYTES)
		  
		  // Calling the overridden superclass constructor.
		  // Constructor(PrivateKeyData As MemoryBlock, PublicKeyData As MemoryBlock) -- From KeyPair
		  Super.Constructor(PrivateKeyData, PublicKeyData)
		  Me.Lock()
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function ConvertSigningKey(FromSigningKey As libsodium.PKI.SigningKey) As libsodium.PKI.EncryptionKey
		  ' Converts the FromSigningKey into a new EncryptionKey
		  
		  Dim priv As New MemoryBlock(crypto_box_SECRETKEYBYTES)
		  Dim pub As New MemoryBlock(crypto_box_PUBLICKEYBYTES)
		  
		  ' first convert the public key
		  If crypto_sign_ed25519_pk_to_curve25519(pub, FromSigningKey.PublicKey) <> 0 Then
		    Raise New SodiumException(ERR_CONVERSION_FAILED)
		  End If
		  
		  ' then the private key
		  If crypto_sign_ed25519_sk_to_curve25519(priv, FromSigningKey.PrivateKey) <> 0 Then
		    Raise New SodiumException(ERR_CONVERSION_FAILED)
		  End If
		  
		  Return New EncryptionKey(priv, pub)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Derive(PrivateKeyData As MemoryBlock) As libsodium.PKI.EncryptionKey
		  ' Given a user's private key, this method generates an EncryptionKey pair
		  
		  Return New EncryptionKey(PrivateKeyData, DerivePublicKey(PrivateKeyData))
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function DerivePublicKey(PrivateKeyData As MemoryBlock) As MemoryBlock
		  ' Given a user's private key, this method computes their public key
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  CheckSize(PrivateKeyData, crypto_scalarmult_BYTES)
		  
		  Dim pub As New MemoryBlock(crypto_scalarmult_BYTES)
		  If crypto_scalarmult_base(pub, PrivateKeyData) = 0 Then Return pub
		  Raise New SodiumException(ERR_COMPUTATION_FAILED)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function DeriveSharedKey(RecipientPublicKey As MemoryBlock) As MemoryBlock
		  ' Calculates the shared key from the RecipientPublicKey and SenderPrivateKey, for
		  ' use with the EncryptData and DecryptData methods. This allows the key derivation
		  ' calculation to be performed once rather than on each invocation of EncryptData
		  ' and DecryptData.
		  
		  Return DeriveSharedKey(Me.PrivateKey, RecipientPublicKey)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function DeriveSharedKey(RecipientPublicKey As MemoryBlock, SenderPrivateKey As MemoryBlock) As MemoryBlock
		  ' Calculates the shared key from the RecipientPublicKey and SenderPrivateKey, for
		  ' use with the EncryptData and DecryptData methods. This allows the key derivation
		  ' calculation to be performed once rather than on each invocation of EncryptData
		  ' and DecryptData.
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  CheckSize(RecipientPublicKey, crypto_box_PUBLICKEYBYTES)
		  CheckSize(SenderPrivateKey, crypto_box_SECRETKEYBYTES)
		  
		  Dim buffer As New MemoryBlock(crypto_box_BEFORENMBYTES)
		  If crypto_box_beforenm(buffer, RecipientPublicKey, SenderPrivateKey) = 0 Then
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function DeriveSharedSecret(RecipientPublicKey As MemoryBlock) As MemoryBlock
		  ' Computes a shared secret given a SenderPrivateKey and RecipientPublicKey.
		  ' The return value represents the X coordinate of a point on the curve. As
		  ' a result, the number of possible keys is limited to the group size (≈2^252),
		  ' and the key distribution is not uniform. For this reason, instead of directly
		  ' using the return value as a shared key, it is recommended to use:
		  '
		  '  GenericHash(return value + RecipientPublicKey + Sender's PUBLIC KEY)
		  
		  CheckSize(RecipientPublicKey, crypto_scalarmult_BYTES)
		  
		  Dim buffer As New MemoryBlock(crypto_scalarmult_BYTES)
		  If crypto_scalarmult(buffer, Me.PrivateKey, RecipientPublicKey) = 0 Then
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1000
		 Shared Function Generate(Optional SeedData As MemoryBlock) As libsodium.PKI.EncryptionKey
		  ' This method randomly generates an EncryptionKey pair, optionally using the specified seed.
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Dim pub As New MemoryBlock(crypto_box_PUBLICKEYBYTES)
		  Dim priv As New MemoryBlock(crypto_box_SECRETKEYBYTES)
		  If SeedData = Nil Then
		    If crypto_box_keypair(pub, priv) = -1 Then Return Nil
		  Else
		    CheckSize(SeedData, crypto_box_SEEDBYTES)
		    If crypto_box_seed_keypair(pub, priv, SeedData) = -1 Then Return Nil
		  End If
		  Return New EncryptionKey(priv, pub)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As libsodium.PKI.EncryptionKey) As Integer
		  If OtherKey Is Nil Then Return 1
		  If libsodium.StrComp(Me.PrivateKey, OtherKey.PrivateKey) Then Return 0
		  Return -1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomNonce() As MemoryBlock
		  ' Returns random bytes that are suitable to be used as a Nonce for use with an EncryptionKey
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Return RandomBytes(crypto_box_NONCEBYTES)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomPrivateKey() As MemoryBlock
		  ' Returns random bytes that are suitable to be used as a private key for encryption. To generate the
		  ' corresponding public key use the EncryptionKey.Derive method.
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Return RandomBytes(crypto_box_SECRETKEYBYTES)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomSeed() As MemoryBlock
		  ' Returns random bytes that are suitable to be used as a seed for EncryptionKey.Generate
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Return RandomBytes(crypto_box_SEEDBYTES)
		End Function
	#tag EndMethod


	#tag ViewBehavior
		#tag ViewProperty
			Name="Index"
			Visible=true
			Group="ID"
			InitialValue="-2147483648"
			InheritedFrom="Object"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Left"
			Visible=true
			Group="Position"
			InheritedFrom="Object"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Name"
			Visible=true
			Group="ID"
			InheritedFrom="Object"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Super"
			Visible=true
			Group="ID"
			InheritedFrom="Object"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Top"
			Visible=true
			Group="Position"
			InitialValue="0"
			InheritedFrom="Object"
		#tag EndViewProperty
	#tag EndViewBehavior
End Class
#tag EndClass
