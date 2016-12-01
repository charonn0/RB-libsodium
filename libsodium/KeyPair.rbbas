#tag Class
Protected Class KeyPair
	#tag Method, Flags = &h1001
		Protected Sub Constructor(PrivateKeyData As libsodium.SecureMemoryBlock, PublicKeyData As libsodium.SecureMemoryBlock)
		  mPrivate = PrivateKeyData
		  mPublic = PublicKeyData
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1000
		Sub Constructor(Optional SeedData As MemoryBlock)
		  Dim pub As New SecureMemoryBlock(crypto_box_PUBLICKEYBYTES)
		  Dim priv As New SecureMemoryBlock(crypto_box_SECRETKEYBYTES)
		  If SeedData = Nil Then
		    mLastError = crypto_box_keypair(pub.TruePtr, priv.TruePtr)
		  Else
		    If SeedData.Size <> crypto_box_SEEDBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		    mLastError = crypto_box_seed_keypair(pub.TruePtr, priv.TruePtr, SeedData)
		  End If
		  If mLastError = 0 Then
		    Me.Constructor(priv, pub)
		    pub.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		    priv.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		  Else
		    Raise New SodiumException(mLastError)
		  End If
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function FromPrivateKey(PrivateKeyData As MemoryBlock) As libsodium.KeyPair
		  If PrivateKeyData.Size <> crypto_box_SECRETKEYBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  Dim priv As New SecureMemoryBlock(crypto_box_SECRETKEYBYTES)
		  Dim pub As New SecureMemoryBlock(crypto_box_PUBLICKEYBYTES)
		  priv.StringValue(0, priv.Size) = PrivateKeyData
		  Dim err As Integer = crypto_scalarmult_base(pub.TruePtr, priv.TruePtr)
		  
		  If err = 0 Then
		    pub.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		    priv.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		    Return New KeyPair(priv, pub)
		  Else
		    Raise New SodiumException(err)
		  End If
		  
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function PrivateKey() As MemoryBlock
		  Dim ret As MemoryBlock
		  Try
		    mPrivate.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		    ret = mPrivate.StringValue(0, mPrivate.Size)
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
		  Finally
		    If mPublic <> Nil Then mPublic.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		  End Try
		  Return ret
		  
		End Function
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mLastError As Integer
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mPrivate As libsodium.SecureMemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mPublic As libsodium.SecureMemoryBlock
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
