#tag Module
Protected Module Version
	#tag Method, Flags = &h1
		Protected Function HasAESNI() As Boolean
		  If System.IsFunctionAvailable("sodium_runtime_has_aesni", sodium) Then
		    Return sodium_runtime_has_aesni = 0
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function HasAVX() As Boolean
		  If System.IsFunctionAvailable("sodium_runtime_has_avx", sodium) Then
		    Return sodium_runtime_has_avx = 0
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function HasAVX2() As Boolean
		  If System.IsFunctionAvailable("sodium_runtime_has_avx2", sodium) Then
		    Return sodium_runtime_has_avx2 = 0
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function HasNeon() As Boolean
		  If System.IsFunctionAvailable("sodium_runtime_has_neon", sodium) Then
		    Return sodium_runtime_has_neon = 0
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function HasPCLMul() As Boolean
		  If System.IsFunctionAvailable("sodium_runtime_has_pclmul", sodium) Then
		    Return sodium_runtime_has_pclmul = 0
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function HasSSE2() As Boolean
		  If System.IsFunctionAvailable("sodium_runtime_has_sse2", sodium) Then
		    Return sodium_runtime_has_sse2 = 0
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function HasSSE3() As Boolean
		  If System.IsFunctionAvailable("sodium_runtime_has_sse3", sodium) Then
		    Return sodium_runtime_has_sse3 = 0
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function HasSSE41() As Boolean
		  If System.IsFunctionAvailable("sodium_runtime_has_sse41", sodium) Then
		    Return sodium_runtime_has_sse41 = 0
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function HasSSSE3() As Boolean
		  If System.IsFunctionAvailable("sodium_runtime_has_ssse3", sodium) Then
		    Return sodium_runtime_has_ssse3 = 0
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function MajorNumber() As Int32
		  If libsodium.IsAvailable Then Return sodium_library_version_major()
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function MinorNumber() As Int32
		  If libsodium.IsAvailable Then Return sodium_library_version_minor()
		End Function
	#tag EndMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_library_version_major Lib sodium () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_library_version_minor Lib sodium () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_aesni Lib sodium () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_avx Lib sodium () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_avx2 Lib sodium () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_neon Lib sodium () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_pclmul Lib sodium () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_sse2 Lib sodium () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_sse3 Lib sodium () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_sse41 Lib sodium () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_ssse3 Lib sodium () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_version_string Lib sodium () As Ptr
	#tag EndExternalMethod

	#tag Method, Flags = &h1
		Protected Function VersionString() As String
		  If Not libsodium.IsAvailable Then Return ""
		  Dim mb As MemoryBlock = sodium_version_string()
		  If mb <> Nil Then Return mb.CString(0)
		End Function
	#tag EndMethod


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
End Module
#tag EndModule
