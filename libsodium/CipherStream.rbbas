#tag Class
Protected Class CipherStream
	#tag Method, Flags = &h0
		Sub Constructor()
		  Me.Constructor(RandomBytes(crypto_stream_KEYBYTES))
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(KeyData As libsodium.PKI.ForeignKey)
		  Me.Constructor(KeyData.Value)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(KeyData As MemoryBlock)
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  CheckSize(KeyData, crypto_stream_KEYBYTES)
		  mKey = New libsodium.SKI.KeyContainer(KeyData)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function DeriveKey(Size As Int32, Optional Nonce As MemoryBlock) As MemoryBlock
		  ' Returns the requested number of bytes from the key stream. Suitable for generating
		  ' keys or other pseudo-random data
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  If Nonce = Nil Then Nonce = Me.RandomNonce()
		  CheckSize(Nonce, crypto_stream_NONCEBYTES)
		  Dim mb As New MemoryBlock(Size)
		  If crypto_stream(mb, mb.Size, Nonce, mKey.Value) <> 0 Then Return Nil
		  Return mb
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Process(Data As MemoryBlock, Nonce As MemoryBlock) As MemoryBlock
		  ' Encrypts or decrypts the Data by XOR'ing it with the key stream.
		  
		  CheckSize(Nonce, crypto_stream_NONCEBYTES)
		  Dim output As New MemoryBlock(Data.Size)
		  If crypto_stream_xor(output, Data, Data.Size, Nonce, mKey.Value) <> 0 Then Return Nil
		  Return output
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomNonce() As MemoryBlock
		  Return RandomBytes(crypto_stream_NONCEBYTES)
		End Function
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mKey As libsodium.SKI.KeyContainer
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
