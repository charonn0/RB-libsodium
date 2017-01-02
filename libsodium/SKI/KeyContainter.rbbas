#tag Class
Protected Class KeyContainter
Implements libsodium.Secureable
	#tag Method, Flags = &h1000
		Sub Constructor(KeyData As MemoryBlock)
		  If mSessionKey = Nil Then mSessionKey = RandomBytes(crypto_secretbox_KEYBYTES)
		  If SessionNonce = Nil Then SessionNonce = libsodium.SKI.SecretKey.RandomNonce
		  mKeyData = libsodium.SKI.EncryptData(KeyData, mSessionKey, SessionNonce)
		  mKeyData.AllowSwap = False
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Lock()
		  // Part of the libsodium.Secureable interface.
		  
		  mKeyData.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Unlock()
		  // Part of the libsodium.Secureable interface.
		  
		  mKeyData.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Value() As MemoryBlock
		  Dim ret As MemoryBlock
		  Try
		    mKeyData.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		    ret = mKeyData.StringValue(0, mKeyData.Size)
		    If mSessionKey <> Nil Then ret = DecryptData(ret, mSessionKey, SessionNonce)
		  Finally
		    If mKeyData <> Nil Then mKeyData.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		  End Try
		  Return ret
		End Function
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mKeyData As libsodium.SecureMemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private Shared mSessionKey As MemoryBlock
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
