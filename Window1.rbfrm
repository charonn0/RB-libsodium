#tag Window
Begin Window Window1
   BackColor       =   &hFFFFFF
   Backdrop        =   ""
   CloseButton     =   True
   Composite       =   False
   Frame           =   0
   FullScreen      =   False
   HasBackColor    =   False
   Height          =   400
   ImplicitInstance=   True
   LiveResize      =   True
   MacProcID       =   0
   MaxHeight       =   32000
   MaximizeButton  =   False
   MaxWidth        =   32000
   MenuBar         =   118499327
   MenuBarVisible  =   True
   MinHeight       =   64
   MinimizeButton  =   True
   MinWidth        =   64
   Placement       =   0
   Resizeable      =   True
   Title           =   "Untitled"
   Visible         =   True
   Width           =   600
End
#tag EndWindow

#tag WindowCode
	#tag Event
		Sub Open()
		  Dim mb As New libsodium.SecureMemoryBlock(64)
		  Dim s As String = "Hello, world!"
		  mb.StringValue(0, s.Len) = s
		  mb.ProtectionLevel = libsodium.MemoryProtectionLevel.NoAccess
		  MsgBox(mb.StringValue(0, s.Len))
		  
		End Sub
	#tag EndEvent


#tag EndWindowCode

