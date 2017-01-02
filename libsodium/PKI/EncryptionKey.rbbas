#tag Class
Protected Class EncryptionKey
Inherits libsodium.PKI.KeyPair
	#tag Method, Flags = &h1000
		Sub Constructor(PasswordData As libsodium.Password)
		  Dim seckey As MemoryBlock = PasswordData.DeriveKey(crypto_box_SECRETKEYBYTES, libsodium.SKI.RandomSalt, _
		  ResourceLimits.Interactive, libsodium.Password.ALG_ARGON2)
		  Dim pubkey As MemoryBlock = libsodium.PKI.DeriveEncryptionKey(seckey)
		  Me.Constructor(seckey, pubkey)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1001
		Protected Sub Constructor(PrivateKeyData As MemoryBlock)
		  CheckSize(PrivateKeyData, crypto_scalarmult_BYTES)
		  Dim pub As New MemoryBlock(crypto_scalarmult_BYTES)
		  If crypto_scalarmult_base(pub, PrivateKeyData) = 0 Then Raise New SodiumException(ERR_COMPUTATION_FAILED)
		  Me.Constructor(PrivateKeyData, pub)
		  
		  
		  
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
		  CheckSize(PrivateKeyData, crypto_box_SECRETKEYBYTES)
		  Dim pub As MemoryBlock = DeriveEncryptionKey(PrivateKeyData)
		  
		  If pub <> Nil Then Return New EncryptionKey(PrivateKeyData, pub)
		  
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
