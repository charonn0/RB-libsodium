#tag Class
Class SecureStream
Implements Readable,Writeable
	#tag Method, Flags = &h0
		Sub Close()
		  Me.Flush
		  mOutput = Nil
		  mInput = Nil
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(KeyData As libsodium.PKI.ForeignKey, Source As Readable, Destination As Writeable, Nonce As MemoryBlock)
		  Me.Constructor(KeyData.Value, Source, Destination, Nonce)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Constructor(KeyData As MemoryBlock, Source As Readable, Destination As Writeable, Nonce As MemoryBlock)
		  CheckSize(KeyData, crypto_stream_KEYBYTES)
		  CheckSize(Nonce, crypto_stream_NONCEBYTES)
		  mNonce = Nonce
		  mInput = Source
		  mOutput = Destination
		  mKey = New libsodium.SKI.KeyContainter(KeyData)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function EOF() As Boolean
		  // Part of the Readable interface.
		  Return mInput.EOF And mReadBuffer.Size = 0
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Flush()
		  // Part of the Writeable interface.
		  If mOutput <> Nil Then mOutput.Flush
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function GetStreamBytes(Count As Int32) As MemoryBlock
		  Dim mb As New MemoryBlock(Count)
		  If crypto_stream(mb, mb.Size, mNonce, mKey.Value) <> 0 Then Return Nil
		  Return mb
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Nonce() As MemoryBlock
		  Return mNonce
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Read(Count As Integer, encoding As TextEncoding = Nil) As String
		  // Part of the Readable interface.
		  If mInput = Nil Then Raise New IOException
		  If mReadBuffer = Nil Then mReadBuffer = New MemoryBlock(0)
		  Dim ret As MemoryBlock
		  If mReadBuffer.Size >= Count Then
		    ret = LeftB(mReadBuffer, Count)
		    mReadBuffer = RightB(mReadBuffer, mReadBuffer.Size - Count)
		  Else
		    Dim bs As New BinaryStream(mReadBuffer)
		    bs.Position = bs.Length
		    Dim stream As MemoryBlock = GetStreamBytes(Count)
		    Do Until bs.Length >= Count
		      Dim mb As MemoryBlock = mInput.Read(BLOCK_SIZE)
		      If crypto_stream_xor(mb, mb, mb.Size, mNonce, mKey.Value) <> 0 Then Raise New IOException
		      bs.Write(mb)
		    Loop
		    bs.Close
		    If mReadBuffer.Size > 0 Then ret = Me.Read(Count, encoding)
		  End If
		  Return DefineEncoding(ret, encoding)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function ReadError() As Boolean
		  // Part of the Readable interface.
		  Return mInput.ReadError
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Write(text As String)
		  // Part of the Writeable interface.
		  If mOutput = Nil Then Raise New IOException
		  If mWriteBuffer = Nil Then mWriteBuffer = New MemoryBlock(0)
		  mWriteBuffer = mWriteBuffer + text
		  Dim bs As New BinaryStream(mWriteBuffer)
		  Do Until bs.EOF
		    Dim mb As MemoryBlock = bs.Read(BLOCK_SIZE)
		    Dim stream As MemoryBlock = GetStreamBytes(mb.Size)
		    If crypto_stream_xor(mb, mb, mb.Size, mNonce, mKey.Value) <> 0 Then Raise New IOException
		    bs.Write(mb)
		  Loop
		  Dim u As UInt64 = bs.Position
		  bs.Close
		  mWriteBuffer = RightB(mWriteBuffer, mWriteBuffer.Size - u)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function WriteError() As Boolean
		  // Part of the Writeable interface.
		  Return mOutput.WriteError
		End Function
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mInput As Readable
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mKey As libsodium.SKI.KeyContainter
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mNonce As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mOutput As Writeable
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mReadBuffer As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mWriteBuffer As MemoryBlock
	#tag EndProperty


	#tag Constant, Name = BLOCK_SIZE, Type = Double, Dynamic = False, Default = \"4096", Scope = Protected
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
