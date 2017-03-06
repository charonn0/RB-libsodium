#tag Class
Protected Class GenericHashDigest
	#tag Method, Flags = &h0
		Sub Constructor(Type As libsodium.HashType = libsodium.HashType.Generic, KeyData As MemoryBlock = Nil)
		  ' Instantiates the processor for hashing. If KeyData is specified then the hash is keyed.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.Constructor
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  mKey = KeyData
		  mType = Type
		  Select Case Type
		  Case HashType.Generic
		    If KeyData <> Nil Then CheckSize(KeyData, crypto_generichash_KEYBYTES)
		    mHashSize = crypto_generichash_BYTES_MAX
		    
		  Case HashType.SHA256
		    If KeyData <> Nil Then CheckSize(KeyData, crypto_auth_hmacsha256_KEYBYTES)
		    mHashSize = crypto_hash_sha256_BYTES
		    
		  Case HashType.SHA512
		    If KeyData <> Nil Then CheckSize(KeyData, crypto_auth_hmacsha512_KEYBYTES)
		    mHashSize = crypto_hash_sha512_BYTES
		    
		  End Select
		  
		  Me.Reset()
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(KeyData As libsodium.Password, Salt As MemoryBlock, Type As libsodium.HashType = libsodium.HashType.Generic)
		  ' Instantiates the processor for hashing using a key derived from KeyData
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.Constructor
		  
		  Dim k As Int32
		  Select Case Type
		  Case HashType.Generic
		    k = crypto_generichash_KEYBYTES
		  Case HashType.SHA256
		    k = crypto_auth_hmacsha256_KEYBYTES
		  Case HashType.SHA512
		    k = crypto_auth_hmacsha512_KEYBYTES
		  End Select
		  
		  Me.Constructor(Type, KeyData.DeriveKey(k, Salt, ResourceLimits.Interactive))
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(HashSize As UInt32, KeyData As MemoryBlock)
		  ' Instantiates the processor for generic hashing.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.Constructor
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  mType = HashType.Generic
		  If KeyData <> Nil Then CheckSize(KeyData, crypto_generichash_KEYBYTES)
		  CheckSize(HashSize, crypto_generichash_BYTES_MIN, crypto_generichash_BYTES_MAX)
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
		 Shared Function RandomKey(Type As libsodium.HashType = libsodium.HashType.Generic) As MemoryBlock
		  ' Returns random bytes that are suitable to be used as a key for GenericHashDigest.Constructor
		  '
		  ' See: 
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.RandomKey
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Select Case Type
		  Case HashType.Generic
		    Return RandomBytes(crypto_generichash_KEYBYTES)
		    
		  Case HashType.SHA256
		    Return RandomBytes(crypto_auth_hmacsha256_KEYBYTES)
		    
		  Case HashType.SHA512
		    Return RandomBytes(crypto_auth_hmacsha512_KEYBYTES)
		    
		  End Select
		  
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
		  Case HashType.Generic
		    sz = crypto_generichash_statebytes()
		  Case HashType.SHA256
		    sz = crypto_hash_sha256_statebytes
		  Case HashType.SHA512
		    sz = crypto_hash_sha512_statebytes
		  End Select
		  
		  mState = New MemoryBlock(sz)
		  
		  If mKey <> Nil Then
		    Select Case mType
		    Case HashType.Generic
		      mLastError = crypto_generichash_init(mState, mKey, mKey.Size, mHashSize)
		    Case HashType.SHA256
		      mLastError = crypto_hash_sha256_init(mState, mKey, mKey.Size)
		    Case HashType.SHA512
		      mLastError = crypto_hash_sha512_init(mState, mKey, mKey.Size)
		    End Select
		  Else
		    Select Case mType
		    Case HashType.Generic
		      mLastError = crypto_generichash_init(mState, Nil, 0, mHashSize)
		    Case HashType.SHA256
		      mLastError = crypto_hash_sha256_init(mState)
		    Case HashType.SHA512
		      mLastError = crypto_hash_sha512_init(mState)
		    End Select
		  End If
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


	#tag Constant, Name = crypto_auth_hmacsha256_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_auth_hmacsha512_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Protected
	#tag EndConstant

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
