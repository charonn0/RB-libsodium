#tag Class
Protected Class EncryptionKey
Inherits libsodium.PKI.KeyPair
	#tag Method, Flags = &h1000
		Sub Constructor(PasswordData As libsodium.Password, Optional Salt As MemoryBlock, Limits As libsodium.ResourceLimits = libsodium.ResourceLimits.Interactive)
		  ' Generates a key pair by deriving it from a password.
		  ' 
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Constructor
		  
		  If Salt <> Nil Then CheckSize(Salt, crypto_pwhash_SALTBYTES) Else Salt = PasswordData.RandomSalt
		  Dim seckey As MemoryBlock = PasswordData.DeriveKey(crypto_box_SECRETKEYBYTES, Salt, Limits, libsodium.Password.ALG_ARGON2)
		  Dim pubkey As MemoryBlock = DerivePublicKey(seckey)
		  Me.Constructor(seckey, pubkey)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1000
		Sub Constructor(FromSigningKey As libsodium.PKI.SigningKey)
		  ' Converts the FromSigningKey(Ed25519) into an EncryptionKey(Curve25519), so that the same 
		  ' key pair can be used both for authenticated encryption and for signatures.
		  ' 
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Constructor
		  
		  Dim priv As New MemoryBlock(crypto_box_SECRETKEYBYTES)
		  Dim pub As New MemoryBlock(crypto_box_PUBLICKEYBYTES)
		  
		  ' first convert the public key
		  If crypto_sign_ed25519_pk_to_curve25519(pub, FromSigningKey.PublicKey) <> 0 Then
		    Dim err As New SodiumException(ERR_CONVERSION_FAILED)
		    err.Message = "This public key cannot be converted."
		    Raise err
		  End If
		  
		  ' then the private key
		  If crypto_sign_ed25519_sk_to_curve25519(priv, FromSigningKey.PrivateKey) <> 0 Then
		    Dim err As New SodiumException(ERR_CONVERSION_FAILED)
		    err.Message = "This private key cannot be converted."
		    Raise err
		  End If
		  
		  Me.Constructor(priv, pub)
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
		 Shared Function Derive(PrivateKeyData As MemoryBlock) As libsodium.PKI.EncryptionKey
		  ' Given a user's private key, this method generates an EncryptionKey pair
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Derive
		  
		  Return New EncryptionKey(PrivateKeyData, DerivePublicKey(PrivateKeyData))
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Shared Function DerivePublicKey(PrivateKeyData As MemoryBlock) As MemoryBlock
		  ' Given a user's private key, this method computes their public key
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  CheckSize(PrivateKeyData, crypto_scalarmult_BYTES)
		  
		  Dim pub As New MemoryBlock(crypto_scalarmult_BYTES)
		  If crypto_scalarmult_base(pub, PrivateKeyData) = 0 Then Return pub
		  Raise New SodiumException(ERR_COMPUTATION_FAILED)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Export() As MemoryBlock
		  ' Exports the EncryptionKey in a format that is understood by EncryptionKey.Import
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Export
		  
		  Dim data As New MemoryBlock(0)
		  Dim bs As New BinaryStream(data)
		  
		  bs.Write(PackKey(Me.PublicKey, PublicPrefix, PublicSuffix))
		  bs.Write(PackKey(Me.PrivateKey, PrivatePrefix, PrivateSuffix))
		  
		  bs.Close
		  Return data
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1000
		 Shared Function Generate(Optional SeedData As MemoryBlock) As libsodium.PKI.EncryptionKey
		  ' This method randomly generates an EncryptionKey pair, optionally using the specified seed.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Generate
		  
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
		 Shared Function Import(ExportedKey As MemoryBlock) As libsodium.PKI.EncryptionKey
		  ' Import an EncryptionKey that was exported using EncryptionKey.Export
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Import
		  
		  'Dim pk As MemoryBlock = ExtractKey(ExportedKey, PublicPrefix, PublicSuffix)
		  Dim sk As MemoryBlock = ExtractKey(ExportedKey, PrivatePrefix, PrivateSuffix)
		  If sk <> Nil Then Return Derive(sk)
		  Return Derive(sk)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As libsodium.PKI.EncryptionKey) As Integer
		  ' This method overloads the comparison operator (=) allowing direct comparisons between 
		  ' instances of EncryptionKey. The comparison operation itself is a constant-time binary 
		  ' comparison of the private key halves of both key pairs; the public halves are not compared.
		  ' 
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Operator_Compare
		  
		  If OtherKey Is Nil Then Return 1
		  If libsodium.StrComp(Me.PrivateKey, OtherKey.PrivateKey) Then Return 0
		  Return -1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomNonce() As MemoryBlock
		  ' Returns random bytes that are suitable to be used as a Nonce for use with an EncryptionKey
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.RandomNonce
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Return RandomBytes(crypto_box_NONCEBYTES)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomPrivateKey() As MemoryBlock
		  ' Returns random bytes that are suitable to be used as a private key for encryption. To generate the
		  ' corresponding public key use the EncryptionKey.Derive method.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.RandomPrivateKey
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Return RandomBytes(crypto_box_SECRETKEYBYTES)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomSeed() As MemoryBlock
		  ' Returns random bytes that are suitable to be used as a seed for EncryptionKey.Generate
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.RandomSeed
		  
		  Return RandomBytes(crypto_box_SEEDBYTES)
		End Function
	#tag EndMethod


	#tag Constant, Name = PrivatePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 PRIVATE KEY BLOCK-----", Scope = Public
	#tag EndConstant

	#tag Constant, Name = PrivateSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 PRIVATE KEY BLOCK-----", Scope = Public
	#tag EndConstant

	#tag Constant, Name = PublicPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 PUBLIC KEY BLOCK-----", Scope = Public
	#tag EndConstant

	#tag Constant, Name = PublicSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 PUBLIC KEY BLOCK-----", Scope = Public
	#tag EndConstant


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
