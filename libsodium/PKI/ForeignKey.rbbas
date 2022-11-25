#tag Class
Protected Class ForeignKey
	#tag Method, Flags = &h0
		Sub Constructor(FromKey As libsodium.PKI.EncryptionKey)
		  ' Instantiates the ForeignKey using the public half of the specified key pair.
		  ' To construct an instance of ForeignKey from the public half of a key pair,
		  ' use ForeignKey.Operator_Convert(String).
		  ' 
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.ForeignKey.Constructor
		  
		  Me.Constructor(FromKey.PublicKey)
		  mType = KeyType.Encryption
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(FromKey As libsodium.PKI.SigningKey)
		  ' Instantiates the ForeignKey using the public half of the specified key pair.
		  ' To construct an instance of ForeignKey from the public half of a key pair,
		  ' use ForeignKey.Operator_Convert(String).
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.ForeignKey.Constructor
		  
		  Me.Constructor(FromKey.PublicKey)
		  mType = KeyType.Signature
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Constructor(KeyData As MemoryBlock)
		  If KeyData.Size < 0 Then Raise New SodiumException(ERR_SIZE_REQUIRED) ' can't pass a MemoryBlock of unknown size
		  mKeyData = KeyData
		  mType = KeyType.Unknown
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Export(SaveTo As FolderItem, Optional Passwd As libsodium.Password, OverWrite As Boolean = False) As Boolean
		  ' Exports the ForeignKey in a format that is understood by ForeignKey.Import(FolderItem)
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.ForeignKey.Export
		  
		  Try
		    Dim bs As BinaryStream = BinaryStream.Create(SaveTo, OverWrite)
		    bs.Write(Me.Export(Passwd))
		    bs.Close
		  Catch Err As IOException
		    Return False
		  End Try
		  Return True
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Export(Optional Passwd As libsodium.Password) As MemoryBlock
		  ' Exports the ForeignKey in a format that is understood by ForeignKey.Import(MemoryBlock)
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.ForeignKey.Export
		  
		  Dim data As New MemoryBlock(0)
		  Dim bs As New BinaryStream(data)
		  Dim t As ExportableType
		  Select Case mType
		  Case KeyType.Signature
		    t = ExportableType.SignPublic
		  Case KeyType.Encryption
		    t = ExportableType.CryptPublic
		  Else
		    t = ExportableType.Unknown
		  End Select
		  bs.Write(libsodium.Exporting.Export(Me.Value, t, Passwd))
		  bs.Close
		  Return data
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Import(ExportedKey As FolderItem, Optional Passwd As libsodium.Password) As libsodium.PKI.ForeignKey
		  ' Import a public key that was exported using ForeignKey.Export(FolderItem)
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.ForeignKey.Import
		  
		  Dim bs As BinaryStream = BinaryStream.Open(ExportedKey)
		  Dim keydata As MemoryBlock = bs.Read(bs.Length)
		  bs.Close
		  Return Import(keydata, Passwd)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Import(KeyData As MemoryBlock, Optional Passwd As libsodium.Password) As libsodium.PKI.ForeignKey
		  ' Import a public key that was exported using ForeignKey.Export() As MemoryBlock
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.ForeignKey.Import
		  
		  Dim typ As KeyType
		  Dim extype As ExportableType = libsodium.Exporting.GetType(KeyData)
		  Dim key As MemoryBlock = libsodium.Exporting.Import(KeyData, Passwd)
		  Select Case extype
		  Case ExportableType.SignPublic
		    typ = KeyType.Signature
		    CheckSize(key, crypto_sign_publickeybytes)
		  Case ExportableType.CryptPublic
		    typ = KeyType.Encryption
		    CheckSize(key, crypto_box_publickeybytes)
		  Case ExportableType.Secret
		    typ = KeyType.Generic
		  Case ExportableType.CryptPrivate, ExportableType.SignPrivate
		    Raise New SodiumException(ERR_WRONG_HALF)
		  Else
		    typ = KeyType.Unknown
		  End Select
		  Dim k As New ForeignKey(key)
		  k.mType = typ
		  Return k
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Length() As Int32
		  ' Returns the size of the ForeignKey, in bytes.
		  ' 
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.ForeignKey.Length
		  
		  Return mKeyData.Size
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As libsodium.PKI.ForeignKey) As Int32
		  ' This method overloads the comparison operator (=) allowing direct comparisons
		  ' between instances of ForeignKey or instances of ForeignKey and Strings. The
		  ' comparison operation itself is a constant-time binary comparison.
		  ' 
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.ForeignKey.Operator_Compare
		  
		  If OtherKey Is Nil Then Return 1
		  If libsodium.StrComp(Me.Value, OtherKey.Value) Then Return 0
		  Return -1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As String) As Int32
		  ' This method overloads the comparison operator (=) allowing direct comparisons
		  ' between instances of ForeignKey or instances of ForeignKey and Strings. The
		  ' comparison operation itself is a constant-time binary comparison.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.ForeignKey.Operator_Compare
		  
		  If libsodium.StrComp(Me.Value, OtherKey) Then Return 0
		  Return -1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Operator_Convert(FromString As String)
		  ' This method overloads the conversion operator (=) allowing direct conversion
		  ' from a String into a new instance of ForeignKey.
		  ' 
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.ForeignKey.Operator_Convert
		  
		  Me.Constructor(FromString)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Value() As MemoryBlock
		  ' Returns the key data.
		  ' 
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.ForeignKey.Value
		  
		  Return mKeyData
		End Function
	#tag EndMethod


	#tag Property, Flags = &h21
		Private mKeyData As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mType As libsodium.PKI.ForeignKey.KeyType
	#tag EndProperty

	#tag ComputedProperty, Flags = &h0
		#tag Getter
			Get
			  return mType
			End Get
		#tag EndGetter
		Type As libsodium.PKI.ForeignKey.KeyType
	#tag EndComputedProperty


	#tag Enum, Name = KeyType, Type = Integer, Flags = &h0
		Encryption
		  Signature
		  Generic
		Unknown
	#tag EndEnum


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
