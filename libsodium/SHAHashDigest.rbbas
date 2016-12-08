#tag Class
Protected Class SHAHashDigest
	#tag Method, Flags = &h0
		Sub Constructor(SHAType As Int32 = libsodium.SHAHashDigest.SHA512)
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  mType = SHAType
		  Me.Reset()
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Process(NewData As MemoryBlock)
		  If mOutput <> Nil Then Raise New SodiumException(ERR_INVALID_STATE)
		  If mType = SHA256 Then
		    mLastError = crypto_hash_sha256_update(mState, NewData, NewData.Size)
		  Else
		    mLastError = crypto_hash_sha512_update(mState, NewData, NewData.Size)
		  End If
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Reset()
		  If mType = SHA256 Then
		    mState = New MemoryBlock(crypto_hash_sha256_BYTES * 2)
		    mLastError = crypto_hash_sha256_init(mState)
		  Else
		    mState = New MemoryBlock(crypto_hash_sha512_BYTES * 2)
		    mLastError = crypto_hash_sha512_init(mState)
		  End If
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Value() As String
		  If mOutput = Nil Then
		    If mType = SHA256 Then
		      mOutput = New MemoryBlock(crypto_hash_sha256_BYTES)
		      mLastError = crypto_hash_sha256_final(mState, mOutput, mOutput.Size)
		    Else
		      mOutput = New MemoryBlock(crypto_hash_sha512_BYTES)
		      mLastError = crypto_hash_sha512_final(mState, mOutput, mOutput.Size)
		    End If
		  End If
		  Return mOutput
		  
		End Function
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mLastError As Int32
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mOutput As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mState As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mType As Int32
	#tag EndProperty


	#tag Constant, Name = crypto_hash_sha256_BYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_hash_sha512_BYTES, Type = Double, Dynamic = False, Default = \"64", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = SHA256, Type = Double, Dynamic = False, Default = \"1", Scope = Public
	#tag EndConstant

	#tag Constant, Name = SHA512, Type = Double, Dynamic = False, Default = \"2", Scope = Public
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
			InitialValue="0"
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
