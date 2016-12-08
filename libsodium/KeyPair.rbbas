#tag Class
Protected Class KeyPair
Implements libsodium.Secureable
	#tag Method, Flags = &h1001
		Protected Sub Constructor(PrivateKeyData As libsodium.SecureMemoryBlock, PublicKeyData As libsodium.SecureMemoryBlock)
		  mSessionKey = libsodium.SKI.RandomKey
		  mSessionKey.AllowSwap = False
		  If SessionNonce = Nil Then SessionNonce = libsodium.SKI.RandomNonce
		  PrivateKeyData.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		  PublicKeyData.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		  mPrivate = libsodium.SKI.EncryptData(PrivateKeyData, mSessionKey, SessionNonce)
		  mPublic = libsodium.SKI.EncryptData(PublicKeyData, mSessionKey, SessionNonce)
		  mPublic.AllowSwap = False
		  mPrivate.AllowSwap = False
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Lock()
		  // Part of the libsodium.Secureable interface.
		  
		  mPublic.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		  mPrivate.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function PrivateKey() As MemoryBlock
		  Dim ret As MemoryBlock
		  Try
		    mPrivate.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		    ret = mPrivate.StringValue(0, mPrivate.Size)
		    ret = libsodium.SKI.DecryptData(ret, mSessionKey, SessionNonce)
		  Finally
		    If mPrivate <> Nil Then mPrivate.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		  End Try
		  Return ret
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function PublicKey() As MemoryBlock
		  Dim ret As MemoryBlock
		  Try
		    mPublic.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		    ret = mPublic.StringValue(0, mPublic.Size)
		    ret = libsodium.SKI.DecryptData(ret, mSessionKey, SessionNonce)
		  Finally
		    If mPublic <> Nil Then mPublic.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		  End Try
		  Return ret
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Unlock()
		  // Part of the libsodium.Secureable interface.
		  
		  mPublic.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		  mPrivate.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		End Sub
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mPrivate As libsodium.SecureMemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mPublic As libsodium.SecureMemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mSessionKey As libsodium.SecureMemoryBlock
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
