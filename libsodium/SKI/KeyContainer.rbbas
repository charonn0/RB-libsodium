#tag Class
Protected Class KeyContainer
Implements libsodium.Secureable
	#tag Method, Flags = &h1000
		Sub Constructor(KeyData As MemoryBlock)
		  ' Creates a new container to hold a copy of the KeyData
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.KeyContainer.Constructor
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  If mSessionKey = Nil Then mSessionKey = RandomBytes(crypto_secretbox_KEYBYTES)
		  If SessionNonce = Nil Then SessionNonce = libsodium.SKI.SecretKey.RandomNonce
		  mKeyData = libsodium.SKI.EncryptData(KeyData, mSessionKey, SessionNonce)
		  mKeyData.AllowSwap = False
		  Me.Lock
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Lock()
		  // Part of the libsodium.Secureable interface.
		  
		  mKeyData.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As String) As Int32
		  ' Performs a constant-time binary comparison to the OtherKey
		  If libsodium.StrComp(Me.Value, OtherKey) Then Return 0
		  Return -1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Unlock()
		  // Part of the libsodium.Secureable interface.
		  
		  mKeyData.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Value() As MemoryBlock
		  ' Returns an unprotected copy of the key.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.KeyContainer.Value
		  
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


	#tag Note, Name = Usage
		This class contains a secret or private key. The key data is encrypted using 
		a SecretKey that is generated at runtime, and stored in a SecureMemoryBlock
		that has been marked as non-swappable. Except when accessed by the Value method
		the encrypted KeyData is also marked as non-readable.
		
	#tag EndNote


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