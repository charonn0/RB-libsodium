#tag Class
Protected Class SecretKey
Implements libsodium.Secureable
	#tag Method, Flags = &h0
		Sub Constructor(FromPassword As libsodium.Password)
		  Dim key As MemoryBlock = FromPassword.DeriveKey(crypto_secretbox_KEYBYTES, RandomSalt, ResourceLimits.Interactive, libsodium.Password.ALG_ARGON2)
		  Me.Constructor(key)
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1001
		Protected Sub Constructor(SecretKeyData As MemoryBlock)
		  If SessionNonce = Nil Then
		    Dim key As MemoryBlock = libsodium.PKI.EncryptionKey.RandomPrivateKey()
		    SessionNonce = libsodium.PKI.EncryptionKey.RandomNonce
		    SessionKey = libsodium.PKI.EncryptionKey.DeriveSharedKey(libsodium.PKI.EncryptionKey.DerivePublicKey(key), key)
		  End If
		  mSecret = libsodium.PKI.EncryptData(SecretKeyData, SessionKey, SessionNonce)
		  mSecret.AllowSwap = False
		  mSecret.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		  
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1000
		 Shared Function Generate() As libsodium.SKI.SecretKey
		  ' Returns random bytes that are suitable to be used as a secret key.
		  
		  Return New libsodium.SKI.SecretKey(RandomBytes(crypto_secretbox_KEYBYTES))
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Lock()
		  // Part of the libsodium.Secureable interface.
		  
		  mSecret.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		End Sub
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

	#tag Method, Flags = &h1
		Protected Sub Unlock()
		  // Part of the libsodium.Secureable interface.
		  
		  mSecret.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Value() As MemoryBlock
		  Dim ret As MemoryBlock
		  Try
		    mSecret.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		    ret = mSecret.StringValue(0, mSecret.Size)
		    If SessionKey <> Nil Then ret = libsodium.PKI.DecryptData(ret, SessionKey, SessionNonce)
		  Finally
		    If mSecret <> Nil Then mSecret.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		  End Try
		  Return ret
		End Function
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mSecret As libsodium.SecureMemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private Shared SessionKey As SecureMemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private Shared SessionNonce As MemoryBlock
	#tag EndProperty


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
