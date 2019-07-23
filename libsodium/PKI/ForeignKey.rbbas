#tag Class
Protected Class ForeignKey
	#tag Method, Flags = &h0
		Sub Constructor(FromKey As libsodium.PKI.EncryptionKey)
		  Me.Constructor(FromKey.PublicKey)
		  mType = KeyType.Encryption
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(FromKey As libsodium.PKI.SigningKey)
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
		  Dim data As New MemoryBlock(0)
		  Dim bs As New BinaryStream(data)
		  Dim t As libsodium.Exporting.ExportableType
		  Select Case mType
		  Case KeyType.Signature
		    t = libsodium.Exporting.ExportableType.SignPublic
		  Case KeyType.Encryption
		    t = libsodium.Exporting.ExportableType.CryptPublic
		  Else
		    t = libsodium.Exporting.ExportableType.Unknown
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
		  Dim typ As KeyType
		  Dim extype As libsodium.Exporting.ExportableType = libsodium.Exporting.GetType(KeyData)
		  Dim key As MemoryBlock = libsodium.Exporting.Import(KeyData, Passwd)
		  Select Case extype
		  Case libsodium.Exporting.ExportableType.SignPublic
		    typ = KeyType.Signature
		    CheckSize(key, crypto_sign_publickeybytes)
		  Case libsodium.Exporting.ExportableType.CryptPublic
		    typ = KeyType.Encryption
		    CheckSize(key, crypto_box_publickeybytes)
		  Case libsodium.Exporting.ExportableType.Secret
		    typ = KeyType.Generic
		  Case libsodium.Exporting.ExportableType.CryptPrivate, libsodium.Exporting.ExportableType.SignPrivate
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
		  Return mKeyData.Size
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As libsodium.PKI.ForeignKey) As Int32
		  If OtherKey Is Nil Then Return 1
		  If libsodium.StrComp(Me.Value, OtherKey.Value) Then Return 0
		  Return -1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As String) As Int32
		  ' Performs a constant-time binary comparison to the OtherKey
		  If libsodium.StrComp(Me.Value, OtherKey) Then Return 0
		  Return -1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Operator_Convert(FromString As String)
		  Me.Constructor(FromString)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Type() As libsodium.PKI.ForeignKey.KeyType
		  Return mType
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Value() As MemoryBlock
		  Return mKeyData
		End Function
	#tag EndMethod


	#tag Property, Flags = &h21
		Private mKeyData As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mType As libsodium.PKI.ForeignKey.KeyType
	#tag EndProperty


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
