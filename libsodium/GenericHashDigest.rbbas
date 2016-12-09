#tag Class
Protected Class GenericHashDigest
	#tag Method, Flags = &h0
		Sub Constructor(Optional KeyData As MemoryBlock)
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  If KeyData <> Nil And KeyData.Size <> crypto_generichash_KEYBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  mKey = KeyData
		  Me.Reset()
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Process(NewData As MemoryBlock)
		  If mOutput <> Nil Then Raise New SodiumException(ERR_INVALID_STATE)
		  mLastError = crypto_generichash_update(mState, NewData, NewData.Size)
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomKey() As MemoryBlock
		  Return libsodium.RandomBytes(crypto_generichash_KEYBYTES)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Reset()
		  Dim sz As UInt64 = crypto_generichash_statebytes()
		  mState = New MemoryBlock(sz)
		  If mKey <> Nil Then
		    mLastError = crypto_generichash_init(mState, mKey, mKey.Size, crypto_generichash_BYTES_MAX)
		  Else
		    mLastError = crypto_generichash_init(mState, Nil, 0, crypto_generichash_BYTES_MAX)
		  End If
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Value() As String
		  If mOutput = Nil Then
		    mOutput = New MemoryBlock(crypto_generichash_BYTES_MAX)
		    mLastError = crypto_generichash_final(mState, mOutput, mOutput.Size)
		  End If
		  Return mOutput
		  
		End Function
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mKey As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mLastError As Int32
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mOutput As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mState As MemoryBlock
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
