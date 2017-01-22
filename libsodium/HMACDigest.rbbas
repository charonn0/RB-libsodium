#tag Class
Protected Class HMACDigest
	#tag Method, Flags = &h0
		Sub Constructor(Type As libsodium.HMACDigest.SHAType, KeyData As MemoryBlock)
		  ' Instantiates the processor for hashing. If KeyData is specified then the hash is keyed.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.HMACDigest.Constructor
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  mKey = KeyData
		  mType = Type
		  Select Case Type
		  Case SHAType.SHA256
		    mHashSize = crypto_auth_hmacsha256_BYTES
		    
		  Case SHAType.SHA512
		    mHashSize = crypto_auth_hmacsha512_BYTES
		    
		  Case SHAType.SHA512_256
		    mHashSize = crypto_auth_hmacsha512256_BYTES
		    
		  End Select
		  
		  Me.Reset()
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(KeyData As libsodium.Password, Salt As MemoryBlock, Type As libsodium.HMACDigest.SHAType)
		  ' Instantiates the processor for hashing. If KeyData is specified then the hash is keyed using a derived key
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.Constructor
		  
		  Dim k As Int32
		  Select Case Type
		  Case SHAType.SHA256
		    k = crypto_auth_hmacsha256_KEYBYTES
		  Case SHAType.SHA512
		    k = crypto_auth_hmacsha512_KEYBYTES
		  Case SHAType.SHA512_256
		    k = crypto_auth_hmacsha512256_KEYBYTES
		  End Select
		  
		  Me.Constructor(Type, KeyData.DeriveKey(k, Salt, ResourceLimits.Interactive))
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub Destructor()
		  If mOutput = Nil And mState <> Nil Then Call Me.Value
		  mState = Nil
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Process(NewData As MemoryBlock)
		  ' Processes the NewData into a running hash.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.Process
		  
		  If mOutput <> Nil Then Raise New SodiumException(ERR_INVALID_STATE)
		  Select Case mType
		  Case SHAType.SHA256
		    mLastError = crypto_auth_hmacsha256_update(mState, NewData, NewData.Size)
		  Case SHAType.SHA512
		    mLastError = crypto_auth_hmacsha512_update(mState, NewData, NewData.Size)
		  Case SHAType.SHA512_256
		    mLastError = crypto_auth_hmacsha512256_update(mState, NewData, NewData.Size)
		  End Select
		  
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomKey() As MemoryBlock
		  ' Returns random bytes that are suitable to be used as a key for GenericHashDigest.Constructor
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.RandomKey
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Return RandomBytes(crypto_generichash_KEYBYTES)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Reset()
		  ' Resets the processor state so that a new hash value can be computed.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.Reset
		  
		  Dim sz As UInt32
		  Select Case mType
		  Case SHAType.SHA256
		    sz = crypto_auth_hmacsha256_BYTES
		  Case SHAType.SHA512
		    sz = crypto_auth_hmacsha512_BYTES
		  Case SHAType.SHA512_256
		    sz = crypto_auth_hmacsha512256_BYTES
		  End Select
		  
		  mState = New MemoryBlock(sz)
		  
		  Select Case mType
		  Case SHAType.SHA256
		    mLastError = crypto_auth_hmacsha256_init(mState, mKey, mKey.Size)
		  Case SHAType.SHA512
		    mLastError = crypto_auth_hmacsha512_init(mState, mKey, mKey.Size)
		  Case SHAType.SHA512_256
		    mLastError = crypto_auth_hmacsha512256_init(mState, mKey, mKey.Size)
		  End Select
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Value() As String
		  ' Finalizes the digest operation and returns the hash value.
		  ' Once you call this method the processor can accept no more input until
		  ' the processor is Reset().
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.Value
		  
		  If mOutput <> Nil Then Return mOutput
		  mOutput = New MemoryBlock(mHashSize)
		  Select Case mType
		  Case SHAType.SHA256
		    mLastError = crypto_auth_hmacsha256_final(mState, mOutput)
		  Case SHAType.SHA512
		    mLastError = crypto_auth_hmacsha512_final(mState, mOutput)
		  Case SHAType.SHA512_256
		    mLastError = crypto_auth_hmacsha512256_final(mState, mOutput)
		  End Select
		  mState = Nil
		  Return mOutput
		  
		  
		End Function
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mHashSize As UInt32
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mKey As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mLastError As Int32
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mOutput As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mState As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mType As libsodium.SHAType
	#tag EndProperty


	#tag Constant, Name = crypto_auth_hmacsha256_BYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_auth_hmacsha256_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_auth_hmacsha512256_BYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_auth_hmacsha512256_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_auth_hmacsha512_BYTES, Type = Double, Dynamic = False, Default = \"64", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_auth_hmacsha512_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Protected
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
