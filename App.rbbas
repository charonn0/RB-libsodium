#tag Class
Protected Class App
Inherits Application
	#tag Event
		Sub Open()
		  If Testing.RunTests() Then
		    MsgBox("All Tests passed!")
		  Else
		    Dim s As String
		    For i As Integer = 0 To UBound(Testing.Failures)
		      s = s + Testing.TestName(Testing.Failures(i))
		      If i < UBound(Testing.Failures) Then s = s  + ", " + EndOfLine
		    Next
		    MsgBox("Test failure(s): " + EndOfLine + s)
		  End If
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
