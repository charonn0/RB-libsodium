#tag Class
Protected Class GenericHashDigest
	#tag Method, Flags = &h0
		Sub Constructor(Type As libsodium.HashType = libsodium.HashType.Generic, KeyData As MemoryBlock = Nil)
		  ' Instantiates the processor for hashing. If KeyData is specified then the hash is keyed.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.Constructor
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Select Case Type
		  Case HashType.Generic
		    Me.Constructor(KeyData, crypto_generichash_BYTES_MAX)
		  Case HashType.SHA256
		    mType = HashType.SHA256
		    mHashSize = crypto_hash_sha256_BYTES
		    Me.Reset()
		  Case HashType.SHA512
		    mType = HashType.SHA512
		    mHashSize = crypto_hash_sha512_BYTES
		    Me.Reset()
		  End Select
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(KeyData As MemoryBlock, HashSize As UInt32)
		  ' Instantiates the processor for generic hashing. If KeyData is specified then
		  ' the hash is keyed.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.Constructor
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  If HashSize > crypto_generichash_BYTES_MAX Or HashSize < crypto_generichash_BYTES_MIN Then Raise New SodiumException(ERR_OUT_OF_RANGE)
		  CheckSize(KeyData, crypto_generichash_KEYBYTES)
		  mType = HashType.Generic
		  mKey = KeyData
		  mHashSize = HashSize
		  Me.Reset()
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
		  Case HashType.Generic
		    mLastError = crypto_generichash_update(mState, NewData, NewData.Size)
		  Case HashType.SHA256
		    mLastError = crypto_hash_sha256_update(mState, NewData, NewData.Size)
		  Case HashType.SHA512
		    mLastError = crypto_hash_sha512_update(mState, NewData, NewData.Size)
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
		  
		  Select Case mType
		  Case HashType.Generic
		    Dim sz As UInt64 = crypto_generichash_statebytes()
		    mState = New MemoryBlock(sz)
		    If mKey <> Nil Then
		      mLastError = crypto_generichash_init(mState, mKey, mKey.Size, mHashSize)
		    Else
		      mLastError = crypto_generichash_init(mState, Nil, 0, mHashSize)
		    End If
		  Case HashType.SHA256
		    mState = New MemoryBlock(crypto_hash_sha256_statebytes)
		    mLastError = crypto_hash_sha256_init(mState)
		  Case HashType.SHA512
		    mState = New MemoryBlock(crypto_hash_sha512_statebytes)
		    mLastError = crypto_hash_sha512_init(mState)
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
		  Case HashType.Generic
		    mLastError = crypto_generichash_final(mState, mOutput, mOutput.Size)
		  Case HashType.SHA256
		    mLastError = crypto_hash_sha256_final(mState, mOutput)
		  Case HashType.SHA512
		    mLastError = crypto_hash_sha512_final(mState, mOutput)
		  End Select
		  Return mOutput
		  
		  
		End Function
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mHashSize As UInt32
	#tag EndProperty

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

	#tag Property, Flags = &h1
		Protected mType As libsodium.HashType
	#tag EndProperty


	#tag Constant, Name = crypto_hash_sha256_BYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_hash_sha512_BYTES, Type = Double, Dynamic = False, Default = \"64", Scope = Protected
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
