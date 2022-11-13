#tag Class
Protected Class PasswordProtectedFile
Implements Readable,Writeable
	#tag Method, Flags = &h0
		Sub Close()
		  If mStream <> Nil Then mStream.Close
		  If mFileSys <> Nil Then mFileSys.Flush()
		  mStream = Nil
		  mFileSys = Nil
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Constructor(Key As libsodium.SKI.SecretKey, FileSys As VirtualVolume)
		  ' This protected constructor is called by the Create() and Open() shared methods.
		  ' Any kind of SecretKey could be used here, not just ones derived from passwords.
		  ' A SharedSecret key could also be used if the Key parameter's datatype were changed accordingly.
		  
		  mFileSys = FileSys
		  If mFileSys.Root.Child("_iv").Exists Then
		    ' decrypt mode
		    mReadable = True
		    Dim payloadstream As BinaryStream = BinaryStream.Open(mFileSys.Root.Child("_payload"))
		    Dim bs As BinaryStream = BinaryStream.Open(mFileSys.Root.Child("_iv"))
		    Dim iv As MemoryBlock = bs.Read(bs.Length)
		    bs.Close
		    mStream = mStream.Open(Key, payloadstream, iv)
		    
		  Else
		    ' encrypt mode
		    mReadable = False
		    Dim payloadstream As BinaryStream = BinaryStream.Create(mFileSys.Root.Child("_payload"))
		    mStream = mStream.Create(Key, payloadstream)
		    Dim bs As BinaryStream = BinaryStream.Create(mFileSys.Root.Child("_iv"))
		    bs.Write(mStream.DecryptionHeader)
		    bs.Close
		    
		  End If
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Create(Destination As FolderItem, Passwd As libsodium.Password) As PasswordProtectedFile
		  ' This method derives a key from the password plus a random salt and then returns a PasswordProtectedFile
		  ' in encrypt/write-only mode.
		  Dim filesys As VirtualVolume = Destination.CreateVirtualVolume()
		  Dim key As New libsodium.SKI.SecretKey(Passwd)
		  Dim bs As BinaryStream = BinaryStream.Create(filesys.Root.Child("_salt"))
		  bs.Write(key.Salt)
		  bs.Close
		  Return New PasswordProtectedFile(key, filesys)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub Destructor()
		  Me.Close()
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function EOF() As Boolean
		  // Part of the Readable interface.
		  
		  Return mReadable And (mStream <> Nil And mStream.EOF)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Flush()
		  // Part of the Writeable interface.
		  
		  If Not mReadable And mStream <> Nil Then mStream.Flush()
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Open(Source As FolderItem, Passwd As libsodium.Password) As PasswordProtectedFile
		  ' This method derives the key from the password plus the salt stored in the file and then returns a PasswordProtectedFile
		  ' in decrypt/read-only mode.
		  Dim filesys As VirtualVolume = Source.OpenAsVirtualVolume()
		  If Not filesys.Root.Child("_salt").Exists Then Raise New libsodium.SodiumException(libsodium.ERR_PARAMETER_CONFLICT)
		  Dim bs As BinaryStream = BinaryStream.Open(filesys.Root.Child("_salt"))
		  Dim salt As MemoryBlock = bs.Read(bs.Length)
		  bs.Close
		  Dim key As New libsodium.SKI.SecretKey(Passwd, salt)
		  Return New PasswordProtectedFile(key, filesys)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Read(Count As Integer, encoding As TextEncoding = Nil) As String
		  // Part of the Readable interface.
		  
		  If mReadable And mStream <> Nil Then Return mStream.Read(Count, encoding)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function ReadError() As Boolean
		  // Part of the Readable interface.
		  
		  Return mReadable And (mStream <> Nil And mStream.ReadError)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Write(text As String)
		  // Part of the Writeable interface.
		  
		  If Not mReadable And mStream <> Nil Then mStream.Write(text)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function WriteError() As Boolean
		  // Part of the Writeable interface.
		  
		  Return Not mReadable And (mStream <> Nil And mStream.WriteError)
		End Function
	#tag EndMethod


	#tag Note, Name = About this class
		A class for password protecting a file.
		https://github.com/charonn0/RB-libsodium/wiki/Examples#putting-it-all-together
		
		This class is a BinaryStream workalike class that encrypts or decrypts a single file
		with a password. The initialization vector for the cipher and the salt for the
		password-based key generator are randomly generated and stored alongside the encrypted
		stream in a Xojo VirtualVolume.
	#tag EndNote


	#tag Property, Flags = &h21
		Private mFileSys As VirtualVolume
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mReadable As Boolean
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mStream As libsodium.SKI.SecretStream
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
