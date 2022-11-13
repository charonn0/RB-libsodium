#tag Class
Protected Class CompressedSecretStream
Inherits libsodium.SKI.SecretStream
	#tag Method, Flags = &h0
		Sub Close()
		  If mCompressor <> Nil Then
		    Dim data As String = mCompressor.Deflate("", zlib.Z_FINISH)
		    mWriteBuffer = mWriteBuffer + data
		  End If
		  Super.Close()
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Constructor(InputStream As Readable, Key As MemoryBlock, Header As MemoryBlock)
		  mDecompressor = New zlib.Inflater(zlib.GZIP_ENCODING)
		  // Calling the overridden superclass constructor.
		  // Constructor(InputStream As Readable, Key As MemoryBlock, Header As MemoryBlock) -- From SecretStream
		  Super.Constructor(InputStream, Key, Header)
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Constructor(OutputStream As Writeable, Key As MemoryBlock)
		  mCompressor = New zlib.Deflater(zlib.Z_DEFAULT_COMPRESSION, zlib.Z_DEFAULT_STRATEGY, zlib.GZIP_ENCODING)
		  // Calling the overridden superclass constructor.
		  // Constructor(OutputStream As Writeable, Key As MemoryBlock) -- From SecretStream
		  Super.Constructor(OutputStream, Key)
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Create(Key As libsodium.SKI.KeyContainer, OutputStream As Writeable) As libsodium.SKI.SecretStream
		  If Key IsA libsodium.Password Then Raise New libsodium.SodiumException(libsodium.ERR_KEYTYPE_MISMATCH)
		  Return New CompressedSecretStream(OutputStream, Key.Value)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Open(Key As libsodium.SKI.KeyContainer, InputStream As Readable, DecryptHeader As FolderItem, HeaderPassword As libsodium.Password = Nil) As libsodium.SKI.SecretStream
		  If Key IsA libsodium.Password Then Raise New libsodium.SodiumException(libsodium.ERR_KEYTYPE_MISMATCH)
		  Dim bs As BinaryStream = BinaryStream.Open(DecryptHeader)
		  Dim metadata As Dictionary
		  Dim header As MemoryBlock = bs.Read(bs.Length)
		  If header.StringValue(0, 5) = "-----" Then header = libsodium.Exporting.Import(header, metadata, HeaderPassword)
		  Return New CompressedSecretStream(InputStream, Key.Value, header)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Open(Key As libsodium.SKI.KeyContainer, InputStream As Readable, DecryptHeader As MemoryBlock, HeaderPassword As libsodium.Password = Nil) As libsodium.SKI.SecretStream
		  If Key IsA libsodium.Password Then Raise New libsodium.SodiumException(libsodium.ERR_KEYTYPE_MISMATCH)
		  Dim metadata As Dictionary
		  If DecryptHeader.StringValue(0, 5) = "-----" Then DecryptHeader = libsodium.Exporting.Import(DecryptHeader, metadata, HeaderPassword)
		  Return New CompressedSecretStream(InputStream, Key.Value, DecryptHeader)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Read(Count As Integer, encoding As TextEncoding = Nil) As String
		  Dim data As String = Super.Read(Count, encoding)
		  If mDecompressor <> Nil Then data = mDecompressor.Inflate(data)
		  Return DefineEncoding(data, encoding)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Write(text As String)
		  If mCompressor <> Nil Then text = mCompressor.Deflate(text, zlib.Z_NO_FLUSH)
		  Super.Write(text)
		End Sub
	#tag EndMethod


	#tag Note, Name = About this class
		A compressed and encrypted data stream.
		https://github.com/charonn0/RB-libsodium/wiki/Compressed-SecretStream-Example
		
		This class is a subclass of the libsodium.SKI.SecretStream class that compresses or decompresses
		the encrypted data stream with GZip. This class uses the zlib module from the RB-zlib project to
		perform compression and decompression, so be sure to have imported it into your project before
		attempting to use this class: https://github.com/charonn0/RB-zlib
		
		CAUTION: Combining compression and encryption can potentially leak information if an attacker can
		control the input. The SecretStream class already mitigates this attack vector by applying padding
		before encrypting, but for maximum security do not use compression if the input is untrusted.
	#tag EndNote


	#tag Property, Flags = &h21
		Private mCompressor As zlib.Deflater
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mDecompressor As zlib.Inflater
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
