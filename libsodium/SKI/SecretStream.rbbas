#tag Class
Protected Class SecretStream
Implements Readable,Writeable
	#tag Method, Flags = &h0
		Sub Close()
		  If mOutput <> Nil Then
		    Me.Write("", Nil, crypto_secretstream_xchacha20poly1305_TAG_FINAL)
		  End If
		  If mInput <> Nil Then
		    #pragma Warning "Fixme"
		  End If
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Constructor(State As MemoryBlock, Header As MemoryBlock, Output As Writeable)
		  mState = State
		  mHeader = Header
		  mOutput = Output
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Constructor(InputStream As Readable, State As MemoryBlock, Header As MemoryBlock)
		  mState = State
		  mHeader = Header
		  mInput = InputStream
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Create(Key As libsodium.SKI.SecretKey, OutputStream As Writeable) As libsodium.SKI.SecretStream
		  If Not System.IsFunctionAvailable("crypto_secretstream_xchacha20poly1305_init_push", "libsodium") Then Raise New SodiumException(ERR_FUNCTION_UNAVAILABLE)
		  Dim state As New MemoryBlock(crypto_stream_chacha20_ietf_KEYBYTES + crypto_stream_chacha20_ietf_NONCEBYTES + 8)
		  Dim header As New MemoryBlock(crypto_secretstream_xchacha20poly1305_HEADERBYTES)
		  
		  If crypto_secretstream_xchacha20poly1305_init_push(state, header, Key.Value) <> 0 Then Raise New SodiumException(ERR_INIT_FAILED)
		  Return New SecretStream(state, header, OutputStream)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function EOF() As Boolean
		  // Part of the Readable interface.
		  
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Flush()
		  // Part of the Writeable interface.
		  Me.Write("", Nil, crypto_secretstream_xchacha20poly1305_TAG_PUSH)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Open(Key As libsodium.SKI.SecretKey, InputStream As Readable) As libsodium.SKI.SecretStream
		  If Not System.IsFunctionAvailable("crypto_secretstream_xchacha20poly1305_init_pull", "libsodium") Then Raise New SodiumException(ERR_FUNCTION_UNAVAILABLE)
		  Dim state As New MemoryBlock(crypto_stream_chacha20_ietf_KEYBYTES + crypto_stream_chacha20_ietf_NONCEBYTES + 8)
		  Dim header As MemoryBlock = InputStream.Read(crypto_secretstream_xchacha20poly1305_HEADERBYTES)
		  
		  If crypto_secretstream_xchacha20poly1305_init_pull(state, header, Key.Value) <> 0 Then Raise New SodiumException(ERR_INIT_FAILED)
		  Return New SecretStream(InputStream, state, header)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Read(Count As Integer, encoding As TextEncoding = Nil) As String
		  // Part of the Readable interface.
		  
		  Dim buffer As New MemoryBlock(Count)
		  Dim cipher As MemoryBlock = mInput.Read(Count)
		  Dim buffersize As UInt32 = buffer.Size
		  Dim tag As UInt32
		  If crypto_secretstream_xchacha20poly1305_pull(mState, buffer, buffersize, tag, cipher, cipher.Size, Nil, 0) <> 0 Then Raise New IOException
		  mEOF = (tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL)
		  buffer.Size = buffersize
		  Return DefineEncoding(buffer, encoding)
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function ReadError() As Boolean
		  // Part of the Readable interface.
		  
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Write(text As String)
		  // Part of the Writeable interface.
		  
		  Me.Write(text, Nil, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Write(Text As String, AdditionalData As MemoryBlock, Tag As UInt32)
		  Dim sz As UInt32 = Text.LenB
		  Dim adsz As UInt32
		  If AdditionalData <> Nil Then
		    adsz = AdditionalData.Size
		    sz = sz + adsz
		  End If
		  Dim buffer As New MemoryBlock(sz)
		  Dim txt As MemoryBlock = Text
		  mWriteError = crypto_secretstream_xchacha20poly1305_push(mState, buffer, sz, txt, txt.Size, AdditionalData, adsz, Tag)
		  If buffer.Size <> sz Then buffer.Size = sz
		  If Not Me.WriteError Then mOutput.Write(buffer)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function WriteError() As Boolean
		  // Part of the Writeable interface.
		  
		  Return mWriteError <> 0
		End Function
	#tag EndMethod


	#tag Property, Flags = &h21
		Private mEOF As Boolean
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mHeader As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mInput As Readable
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mOutput As Writeable
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mState As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mWriteError As Integer
	#tag EndProperty


	#tag Constant, Name = crypto_secretstream_xchacha20poly1305_TAG_FINAL, Type = Double, Dynamic = False, Default = \"3", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE, Type = Double, Dynamic = False, Default = \"0", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_secretstream_xchacha20poly1305_TAG_PUSH, Type = Double, Dynamic = False, Default = \"1", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_secretstream_xchacha20poly1305_TAG_REKEY, Type = Double, Dynamic = False, Default = \"2", Scope = Private
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
