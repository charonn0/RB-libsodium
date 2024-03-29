#tag Class
Protected Class SecretStream
Implements Readable,Writeable
	#tag Method, Flags = &h0
		Sub Close()
		  ' Closes the stream and releases all resources. If there are any bytes
		  ' remaining in the write buffer then they are padded to fill a full
		  ' block and written to the stream with the TAG_FINAL tag.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.Close
		  
		  If mOutput <> Nil Then
		    If mWriteBuffer.LenB > 0 Then
		      mDataSize = mDataSize + mWriteBuffer.LenB
		      Do Until mWriteBuffer.LenB = 0
		        Dim data As MemoryBlock = LeftB(mWriteBuffer, mBlockSize)
		        mWriteBuffer = RightB(mWriteBuffer, mWriteBuffer.LenB - mBlockSize)
		        Dim tag As UInt8 = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
		        If data.Size < mBlockSize Then
		          libsodium.PadData(data, mBlockSize)
		          tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL
		        End If
		        Me.Write(data, tag)
		      Loop
		    End If
		    If mData <> Nil And mData.Size <> mDataSize Then mData.Size = mDataSize
		  End If
		  mInput = Nil
		  mOutput = Nil
		  mData = Nil
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(Buffer As MemoryBlock, Key As libsodium.PKI.SharedSecret, DecryptHeader As MemoryBlock = Nil, HeaderPassword As libsodium.Password = Nil)
		  ' Constructs an in-memory SecretStream. If the Buffer size is zero then an encryption stream is created,
		  ' otherwise a decryption stream is created. Decryption requires the original decryption header.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.Constructor
		  
		  Me.Constructor(Buffer, Key.Value, DecryptHeader, HeaderPassword)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(Buffer As MemoryBlock, Key As libsodium.SKI.SecretKey, DecryptHeader As MemoryBlock = Nil, HeaderPassword As libsodium.Password = Nil)
		  ' Constructs an in-memory SecretStream. If the Buffer size is zero then an encryption stream is created,
		  ' otherwise a decryption stream is created. Decryption requires the original decryption header.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.Constructor
		  
		  Me.Constructor(Buffer, Key.Value, DecryptHeader, HeaderPassword)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Constructor(Buffer As MemoryBlock, Key As MemoryBlock, DecryptHeader As MemoryBlock, HeaderPassword As libsodium.Password)
		  ' Constructs an in-memory SecretStream. If the Buffer size is zero then an encryption stream is created,
		  ' otherwise a decryption stream is created. Decryption requires the original decryption header.
		  
		  Dim metadata As Dictionary
		  If DecryptHeader <> Nil And DecryptHeader.StringValue(0, 5) = "-----" Then
		    DecryptHeader = libsodium.Exporting.Import(DecryptHeader, metadata, HeaderPassword)
		  End If
		  
		  Select Case True
		  Case Buffer.Size > 0 And DecryptHeader <> Nil ' readable
		    Me.Constructor(New BinaryStream(Buffer), Key, DecryptHeader)
		  Case Buffer.Size = 0 And DecryptHeader = Nil ' writeable
		    Me.Constructor(New BinaryStream(Buffer), Key)
		  Case Buffer.Size < 0
		    Raise New SodiumException(ERR_SIZE_REQUIRED)
		  Case Buffer.Size > 0 And DecryptHeader <> Nil
		    Raise New SodiumException(ERR_PARAMETER_CONFLICT)
		  End Select
		  mData = Buffer
		  mDataSize = 0
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Constructor(InputStream As Readable, Key As MemoryBlock, Header As MemoryBlock)
		  ' Construct a decryption stream from the InputStream, Key, and Header parameters.
		  
		  If Not libsodium.IsAvailable Or Not System.IsFunctionAvailable("crypto_secretstream_xchacha20poly1305_init_pull", sodium) Then Raise New SodiumException(ERR_FUNCTION_UNAVAILABLE)
		  If Left(Header, 5) = "-----" Then Header = libsodium.Exporting.DecodeMessage(Header)
		  CheckSize(Header, crypto_secretstream_xchacha20poly1305_headerbytes)
		  CheckSize(Key, crypto_secretstream_xchacha20poly1305_keybytes)
		  
		  mState = New MemoryBlock(crypto_secretstream_xchacha20poly1305_statebytes)
		  mHeader = Header
		  If crypto_secretstream_xchacha20poly1305_init_pull(mState, mHeader, Key) <> 0 Then Raise New SodiumException(ERR_INIT_FAILED)
		  mInput = InputStream
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Constructor(OutputStream As Writeable, Key As MemoryBlock)
		  ' Construct a new encryption stream using the specified key.
		  
		  If Not libsodium.IsAvailable Or Not System.IsFunctionAvailable("crypto_secretstream_xchacha20poly1305_init_push", sodium) Then Raise New SodiumException(ERR_FUNCTION_UNAVAILABLE)
		  CheckSize(Key, crypto_secretstream_xchacha20poly1305_keybytes)
		  
		  mState = New MemoryBlock(crypto_secretstream_xchacha20poly1305_statebytes)
		  mHeader = New MemoryBlock(crypto_secretstream_xchacha20poly1305_headerbytes)
		  If crypto_secretstream_xchacha20poly1305_init_push(mState, mHeader, Key) <> 0 Then Raise New SodiumException(ERR_INIT_FAILED)
		  mOutput = OutputStream
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Create(Key As libsodium.PKI.SharedSecret, OutputStream As Writeable) As libsodium.SKI.SecretStream
		  ' Creates a new encrypted stream in the OutputStream using the specified shared key.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.Create
		  
		  Return New SecretStream(OutputStream, Key.Value)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Create(Key As libsodium.SKI.SecretKey, OutputStream As Writeable) As libsodium.SKI.SecretStream
		  ' Creates a new encrypted stream in the OutputStream using the specified secret key.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.Create
		  
		  Return New SecretStream(OutputStream, Key.Value)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function EndOfFile() As Boolean
		  // Part of the Readable interface.
		  Return Me.EOF()
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function EOF() As Boolean
		  // Part of the Readable interface.
		  ' Returns True if there are no more bytes to read from the encrypted stream.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.EOF
		  
		  Return (mEOF Or (mInput <> Nil And mInput.EOF)) And mReadBuffer.LenB = 0
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function ExportDecryptionHeader(SaveTo As FolderItem, Optional Passwd As libsodium.Password, OverWrite As Boolean = False) As Boolean
		  ' Exports the decryption header (initialization vector) in a format that is understood by SecretStream.Open
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.ExportDecryptionHeader
		  
		  Try
		    Dim bs As BinaryStream = BinaryStream.Create(SaveTo, OverWrite)
		    bs.Write(Me.ExportDecryptionHeader(Passwd))
		    bs.Close
		  Catch Err As IOException
		    Return False
		  End Try
		  Return True
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function ExportDecryptionHeader(Optional Passwd As libsodium.Password) As MemoryBlock
		  ' Exports the decryption header (initialization vector) in a format that is understood by SecretStream.Open
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.ExportDecryptionHeader
		  
		  Return libsodium.Exporting.Export(mHeader, ExportableType.StateHeader, Passwd)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Flush()
		  // Part of the Writeable interface.
		  ' Flushes the stream (encryption mode only.)
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.Flush
		  
		  If mOutput <> Nil Then mOutput.Flush
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function GenerateKey() As libsodium.SKI.SecretKey
		  ' Generate a new secret key for use with this class.
		  ' 
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.GenerateKey
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  If System.IsFunctionAvailable("crypto_secretstream_xchacha20poly1305_keygen", sodium) Then
		    Dim k As New MemoryBlock(crypto_secretstream_xchacha20poly1305_keybytes)
		    crypto_secretstream_xchacha20poly1305_keygen(k)
		    If k.IsZero Then Raise New SodiumException(ERR_KEYGEN_FAILED)
		    Return SecretKey.Derive(k)
		  Else
		    Return SecretKey.Generate()
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function IsReadable() As Boolean
		  ' Returns True if the stream is in decryption mode.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.IsReadable
		  
		  Return mInput <> Nil
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function IsWriteable() As Boolean
		  ' Returns True if the stream is in encryption mode.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.IsWriteable
		  
		  Return mOutput <> Nil
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Open(Key As libsodium.PKI.SharedSecret, InputStream As Readable, DecryptHeader As FolderItem, HeaderPassword As libsodium.Password = Nil) As libsodium.SKI.SecretStream
		  ' Opens the encrypted stream represented by InputStream using the specified
		  ' shared key and initialization vector/DecryptHeader.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.Open
		  
		  Dim bs As BinaryStream = BinaryStream.Open(DecryptHeader)
		  Dim metadata As Dictionary
		  Dim header As MemoryBlock = bs.Read(bs.Length)
		  If header.StringValue(0, 5) = "-----" Then header = libsodium.Exporting.Import(header, metadata, HeaderPassword)
		  Return New SecretStream(InputStream, Key.Value, header)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Open(Key As libsodium.PKI.SharedSecret, InputStream As Readable, DecryptHeader As MemoryBlock, HeaderPassword As libsodium.Password = Nil) As libsodium.SKI.SecretStream
		  ' Opens the encrypted stream represented by InputStream using the specified
		  ' shared key and initialization vector/DecryptHeader.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.Open
		  
		  Dim metadata As Dictionary
		  If DecryptHeader.StringValue(0, 5) = "-----" Then DecryptHeader = libsodium.Exporting.Import(DecryptHeader, metadata, HeaderPassword)
		  Return New SecretStream(InputStream, Key.Value, DecryptHeader)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Open(Key As libsodium.SKI.SecretKey, InputStream As Readable, DecryptHeader As FolderItem, HeaderPassword As libsodium.Password = Nil) As libsodium.SKI.SecretStream
		  ' Opens the encrypted stream represented by InputStream using the specified
		  ' secret key and initialization vector/DecryptHeader.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.Open
		  
		  Dim bs As BinaryStream = BinaryStream.Open(DecryptHeader)
		  Dim metadata As Dictionary
		  Dim header As MemoryBlock = bs.Read(bs.Length)
		  If header.StringValue(0, 5) = "-----" Then header = libsodium.Exporting.Import(header, metadata, HeaderPassword)
		  Return New SecretStream(InputStream, Key.Value, header)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Open(Key As libsodium.SKI.SecretKey, InputStream As Readable, DecryptHeader As MemoryBlock, HeaderPassword As libsodium.Password = Nil) As libsodium.SKI.SecretStream
		  ' Opens the encrypted stream represented by InputStream using the specified
		  ' secret key and initialization vector/DecryptHeader.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.Open
		  
		  Dim metadata As Dictionary
		  If DecryptHeader.StringValue(0, 5) = "-----" Then DecryptHeader = libsodium.Exporting.Import(DecryptHeader, metadata, HeaderPassword)
		  Return New SecretStream(InputStream, Key.Value, DecryptHeader)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Read(Count As Integer, AdditionalData As MemoryBlock) As String
		  ' Reads the specified number of encrypted bytes. If the bytes were successfully decrypted and
		  ' authenticated then the decrypted bytes are returned. AdditionalData is extra data that was
		  ' used by the encryptor when computing the authentication code.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.Read
		  
		  Dim tag As UInt8
		  Return Me.Read(Count, AdditionalData, tag)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function Read(Count As Integer, AdditionalData As MemoryBlock, ByRef Tag As UInt8) As String
		  ' This method reads an encrypted block+authentication code from the stream, and validates
		  ' the block and the AdditionalData against the authentication code. If the block+AdditionalData
		  ' are authentic then the decrypted block is returned and the Tag parameter is set to one of these
		  ' constants:
		  '
		  '   crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
		  '   crypto_secretstream_xchacha20poly1305_TAG_PUSH
		  '   crypto_secretstream_xchacha20poly1305_TAG_REKEY
		  '   crypto_secretstream_xchacha20poly1305_TAG_FINAL
		  '
		  ' Refer to the libsodium documentation for the meanings of these tags.
		  
		  Dim cipher As MemoryBlock = mInput.Read(Count + crypto_secretstream_xchacha20poly1305_abytes)
		  If cipher.Size = 0 Then mEOF = mInput.EOF
		  Dim buffer As New MemoryBlock(cipher.Size - crypto_secretstream_xchacha20poly1305_abytes)
		  Dim buffersize As UInt64 = buffer.Size
		  Dim ad As Ptr
		  Dim adsz As UInt64
		  If AdditionalData <> Nil Then
		    ad = AdditionalData
		    adsz = AdditionalData.Size
		  End If
		  
		  mReadError = crypto_secretstream_xchacha20poly1305_pull(mState, buffer, buffersize, tag, cipher, cipher.Size, ad, adsz)
		  If mReadError = 0 Then
		    mEOF = (tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL) Or (buffersize = 0)
		    If mEOF And buffersize > 0 Then libsodium.UnpadData(buffer, mBlockSize)
		    Return buffer
		  End If
		  If Not mEOF Then Raise New SodiumException(ERR_DECRYPT_FAIL)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Read(Count As Integer, encoding As TextEncoding = Nil) As String Implements Readable.Read
		  // Part of the Readable interface.
		  ' Reads the specified number of encrypted bytes. If the bytes were successfully decrypted and
		  ' authenticated then the decrypted bytes are returned.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.Read
		  
		  Do Until Count <= mReadBuffer.LenB Or mInput.EOF Or mEOF
		    Dim ad As New MemoryBlock(0)
		    Dim tag As UInt8
		    mReadBuffer = mReadBuffer + Me.Read(mBlockSize, ad, tag)
		  Loop
		  
		  Dim data As String = LeftB(mReadBuffer, Count)
		  Dim sz As Integer = Max(mReadBuffer.LenB - Count, 0)
		  mReadBuffer = RightB(mReadBuffer, sz)
		  Return DefineEncoding(data, encoding)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function Read(Count As Integer, ByRef Tag As UInt8) As String
		  ' This method reads an encrypted block+authentication code from the stream, and validates
		  ' the block against the authentication code. If the block is authentic then the decrypted
		  ' block is returned and the Tag parameter is set to one of these constants:
		  '
		  '   crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
		  '   crypto_secretstream_xchacha20poly1305_TAG_PUSH
		  '   crypto_secretstream_xchacha20poly1305_TAG_REKEY
		  '   crypto_secretstream_xchacha20poly1305_TAG_FINAL
		  '
		  ' Refer to the libsodium documentation for the meanings of these tags.
		  
		  Dim ad As New MemoryBlock(0)
		  Return Me.Read(Count, ad, Tag)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function ReadError() As Boolean
		  // Part of the Readable interface.
		  
		  Return mReadError <> 0
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Rekey()
		  ' Explicitly rekeys the stream. Ordinarily done automatically.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.Rekey
		  
		  If mState <> Nil Then crypto_secretstream_xchacha20poly1305_rekey(mState)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Write(text As String) Implements Writeable.Write
		  // Part of the Writeable interface.
		  ' Encrypts the Text and computes an authentication code based on the Text and writes
		  ' the encrypted bytes and the authentication code to the output stream.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.Write
		  
		  
		  mWriteBuffer = mWriteBuffer + text
		  Do Until mWriteBuffer.LenB < mBlockSize
		    Dim data As String = LeftB(mWriteBuffer, mBlockSize)
		    mWriteBuffer = RightB(mWriteBuffer, mWriteBuffer.LenB - mBlockSize)
		    Me.Write(data, Nil, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
		  Loop
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Write(Text As String, AdditionalData As MemoryBlock)
		  ' Encrypts the Text and computes an authentication code based on the Text and the AdditionalData
		  ' and writes the encrypted bytes and the authentication code to the output stream.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.Write
		  
		  Me.Write(Text, AdditionalData, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Write(Text As String, AdditionalData As MemoryBlock, Tag As UInt8)
		  ' Encrypts the Text and computes an authentication code based on the Text and the AdditionalData
		  ' and writes the encrypted bytes and the authentication code to the output stream. Tag is one of
		  ' these constants:
		  '
		  '   crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
		  '   crypto_secretstream_xchacha20poly1305_TAG_PUSH
		  '   crypto_secretstream_xchacha20poly1305_TAG_REKEY
		  '   crypto_secretstream_xchacha20poly1305_TAG_FINAL
		  '
		  ' Refer to the libsodium documentation for the meanings of these tags.
		  
		  Dim sz As UInt64 = Text.LenB
		  Dim adsz As UInt64
		  Dim ad As Ptr
		  If AdditionalData <> Nil Then
		    adsz = AdditionalData.Size
		    ad = AdditionalData
		  End If
		  sz = sz + adsz
		  Dim buffer As New MemoryBlock(sz + crypto_secretstream_xchacha20poly1305_abytes)
		  Dim txt As MemoryBlock = Text
		  mWriteError = crypto_secretstream_xchacha20poly1305_push(mState, buffer, sz, txt, txt.Size, ad, adsz, Tag)
		  If buffer.Size <> sz Then buffer.Size = sz
		  mDataSize = mDataSize + buffer.Size
		  If Not Me.WriteError Then mOutput.Write(buffer)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Write(Text As String, Tag As UInt8)
		  ' Encrypts the Text and computes an authentication code based on the Text and writes the
		  ' encrypted bytes and the authentication code to the output stream. Tag is one of these
		  ' constants:
		  '
		  '   crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
		  '   crypto_secretstream_xchacha20poly1305_TAG_PUSH
		  '   crypto_secretstream_xchacha20poly1305_TAG_REKEY
		  '   crypto_secretstream_xchacha20poly1305_TAG_FINAL
		  '
		  ' Refer to the libsodium documentation for the meanings of these tags.
		  
		  Me.Write(Text, Nil, Tag)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function WriteError() As Boolean
		  // Part of the Writeable interface.
		  
		  Return mWriteError <> 0
		End Function
	#tag EndMethod


	#tag ComputedProperty, Flags = &h0
		#tag Getter
			Get
			  ' Gets the size of the blocks that are written/read when using the
			  ' buffered write/read methods. The same block size must be used for
			  ' both encryption and decryption.
			  
			  ' The Close() method pads the final block of encrypted data to equal
			  ' the block size.
			  ' 
			  ' See:
			  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.BlockSize
			  
			  return mBlockSize
			End Get
		#tag EndGetter
		#tag Setter
			Set
			  ' Sets the size of the blocks that are written/read when using the
			  ' buffered write/read methods. The same block size must be used for
			  ' both encryption and decryption.
			  
			  ' The Close() method pads the final block of encrypted data to equal
			  ' the block size.
			  '
			  ' See:
			  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.BlockSize
			  
			  value = Max(value, 1024 * 16)
			  mBlockSize = value
			End Set
		#tag EndSetter
		BlockSize As Int32
	#tag EndComputedProperty

	#tag ComputedProperty, Flags = &h0
		#tag Getter
			Get
			  ' Returns the decryption header/initialization vector. This header is needed
			  ' for decryption and must be transmitted with the encrypted stream.
			  '
			  ' See:
			  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretStream.DecryptionHeader
			  
			  Return mHeader
			End Get
		#tag EndGetter
		DecryptionHeader As MemoryBlock
	#tag EndComputedProperty

	#tag Property, Flags = &h21
		Private mBlockSize As Int32 = &hFFFF
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mData As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mDataSize As UInt32
	#tag EndProperty

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
		Private mReadBuffer As String
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mReadError As Integer
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mState As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mWriteBuffer As String
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mWriteError As Integer
	#tag EndProperty


	#tag Constant, Name = crypto_secretstream_xchacha20poly1305_TAG_FINAL, Type = Double, Dynamic = False, Default = \"3", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE, Type = Double, Dynamic = False, Default = \"0", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_secretstream_xchacha20poly1305_TAG_PUSH, Type = Double, Dynamic = False, Default = \"1", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_secretstream_xchacha20poly1305_TAG_REKEY, Type = Double, Dynamic = False, Default = \"2", Scope = Protected
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
