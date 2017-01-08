#tag Class
Protected Class App
Inherits Application
	#tag Event
		Sub Open()
		  Dim master As libsodium.PKI.EncryptionKey
		  master = master.Generate
		  Dim s As MemoryBlock = master.RandomSalt
		  Dim child As libsodium.PKI.EncryptionKey = master.DeriveSubkey(s, master.RandomSalt)
		  
		  Dim m, c As FolderItem
		  m = SpecialFolder.Desktop.Child("MASTER.KEY")
		  c = SpecialFolder.Desktop.Child("CHILD.KEY")
		  If Not master.Export(m) Then Break
		  If Not child.Export(c) Then Break
		  Dim salt As String = EncodeHex(s)
		  Break
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
