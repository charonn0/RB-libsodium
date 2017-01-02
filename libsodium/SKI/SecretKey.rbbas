#tag Class
Protected Class SecretKey
Inherits libsodium.SKI.KeyContainter
Implements libsodium.Secureable
	#tag Method, Flags = &h0
		Sub Constructor(FromPassword As libsodium.Password, Optional Salt As MemoryBlock, Limits As libsodium.ResourceLimits = libsodium.ResourceLimits.Interactive, HashAlgorithm As Int32 = libsodium.Password.ALG_ARGON2)
		  ' Compute a SecretKey from a hash of the password
		  If Salt <> Nil Then CheckSize(Salt, crypto_pwhash_SALTBYTES) Else Salt = RandomSalt
		  Dim key As MemoryBlock = FromPassword.DeriveKey(crypto_secretbox_KEYBYTES, Salt, Limits, HashAlgorithm)
		  Super.Constructor(key)
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1001
		Protected Sub Constructor(KeyData As MemoryBlock)
		  // Calling the overridden superclass constructor.
		  Super.Constructor(KeyData)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1000
		 Shared Function Generate() As libsodium.SKI.SecretKey
		  ' Returns random bytes that are suitable to be used as a secret key.
		  
		  Return New libsodium.SKI.SecretKey(RandomBytes(crypto_secretbox_KEYBYTES))
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As libsodium.SKI.SecretKey) As Integer
		  If OtherKey Is Nil Then Return 1
		  If libsodium.StrComp(Me.Value, OtherKey.Value) Then Return 0
		  Return -1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomNonce() As MemoryBlock
		  ' Returns random bytes that are suitable to be used as a Nonce.
		  
		  Return RandomBytes(crypto_secretbox_NONCEBYTES)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomSalt() As MemoryBlock
		  ' Returns random bytes that are suitable to be used as a salt.
		  
		  Return RandomBytes(crypto_pwhash_SALTBYTES)
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
