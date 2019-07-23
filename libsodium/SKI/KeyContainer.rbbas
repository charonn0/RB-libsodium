#tag Class
Protected Class KeyContainer
	#tag Method, Flags = &h1000
		Sub Constructor(KeyData As MemoryBlock)
		  ' Creates a new container to hold a copy of the KeyData. The KeyData is encrypted
		  ' and stored in a SecureMemoryBlock.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.KeyContainer.Constructor
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  If KeyData.Size < 0 Then Raise New SodiumException(ERR_SIZE_REQUIRED) ' can't pass a MemoryBlock of unknown size
		  If RuntimeKey = Nil Then RuntimeKey = RandomBytes(crypto_secretbox_keybytes)
		  mSessionNonce = libsodium.SKI.SecretKey.RandomNonce
		  mKeyData = libsodium.SKI.EncryptData(KeyData, RuntimeKey, mSessionNonce)
		  mKeyData.AllowSwap = False
		  mKeyData.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As libsodium.SKI.KeyContainer) As Int32
		  ' Performs a constant-time binary comparison to the OtherKey
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.KeyContainer.Operator_Compare
		  
		  Return Me.Operator_Compare(OtherKey.Value)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As String) As Int32
		  ' Performs a constant-time binary comparison to the OtherKey
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.KeyContainer.Operator_Compare
		  
		  If libsodium.StrComp(Me.Value, OtherKey) Then Return 0
		  Return -1
		End Function
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
		    If RuntimeKey <> Nil Then ret = libsodium.SKI.DecryptData(ret, RuntimeKey, mSessionNonce)
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
		Private mSessionNonce As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private Shared RuntimeKey As MemoryBlock
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
