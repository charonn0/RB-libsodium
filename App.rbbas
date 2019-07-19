#tag Class
Protected Class App
Inherits Application
	#tag Event
		Sub Open()
		  Dim infile As FolderItem = GetFolderItem("D:\Installers\ISO\UT3\UT3.iso")
		  Dim outfile As FolderItem = SpecialFolder.Desktop.Child(infile.Name + ".crypt")
		  Dim instream As BinaryStream = BinaryStream.Open(infile)
		  Dim outstream As BinaryStream = BinaryStream.Create(outfile)
		  Dim stream As libsodium.SKI.SecretStream
		  Dim p As libsodium.Password = "seekrit"
		  Dim key As New libsodium.SKI.SecretKey(p)
		  
		  stream = stream.Create(key, outstream)
		  'stream.CompressionType = stream.CompressAsGZip
		  'stream.CompressionLevel = 9
		  Do Until instream.EOF
		    stream.Write(instream.Read(&hFFFF))
		  Loop
		  stream.Close
		  outstream.Close
		  instream.Close
		  
		  
		  
		  instream = BinaryStream.Open(outfile)
		  Dim decrypt As FolderItem = SpecialFolder.Desktop.Child("decrypted_" + infile.Name)
		  outstream = BinaryStream.Create(decrypt)
		  stream = stream.Open(key, instream, stream.DecryptionHeader)
		  'stream.CompressionType = stream.CompressAsGZip
		  Do Until stream.EOF
		    outstream.Write(stream.Read(&hFFFF))
		  Loop
		  outstream.Close
		  stream.Close
		  instream.Close
		  
		End Sub
	#tag EndEvent


	#tag Constant, Name = kEditClear, Type = String, Dynamic = False, Default = \"&Delete", Scope = Public
		#Tag Instance, Platform = Windows, Language = Default, Definition  = \"&Delete"
		#Tag Instance, Platform = Linux, Language = Default, Definition  = \"&Delete"
	#tag EndConstant

	#tag Constant, Name = kFileQuit, Type = String, Dynamic = False, Default = \"&Quit", Scope = Public
		#Tag Instance, Platform = Windows, Language = Default, Definition  = \"E&xit"
	#tag EndConstant

	#tag Constant, Name = kFileQuitShortcut, Type = String, Dynamic = False, Default = \"", Scope = Public
		#Tag Instance, Platform = Mac OS, Language = Default, Definition  = \"Cmd+Q"
		#Tag Instance, Platform = Linux, Language = Default, Definition  = \"Ctrl+Q"
	#tag EndConstant


	#tag ViewBehavior
	#tag EndViewBehavior
End Class
#tag EndClass
