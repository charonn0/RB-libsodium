#tag Module
Protected Module Version
	#tag Method, Flags = &h1
		Protected Function HasAESNI() As Boolean
		  If System.IsFunctionAvailable("sodium_runtime_has_aesni", "libsodium") Then 
		    Return sodium_runtime_has_aesni = 0
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function HasAVX() As Boolean
		  If System.IsFunctionAvailable("sodium_runtime_has_avx", "libsodium") Then 
		    Return sodium_runtime_has_avx = 0
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function HasAVX2() As Boolean
		  If System.IsFunctionAvailable("sodium_runtime_has_avx2", "libsodium") Then 
		    Return sodium_runtime_has_avx2 = 0
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function HasNeon() As Boolean
		  If System.IsFunctionAvailable("sodium_runtime_has_neon", "libsodium") Then 
		    Return sodium_runtime_has_neon = 0
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function HasPCLMul() As Boolean
		  If System.IsFunctionAvailable("sodium_runtime_has_pclmul", "libsodium") Then 
		    Return sodium_runtime_has_pclmul = 0
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
		Private Soft Declare Function sodium_library_version_major Lib "libsodium" () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_library_version_minor Lib "libsodium" () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_aesni Lib "libsodium" () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_avx Lib "libsodium" () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_avx2 Lib "libsodium" () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_neon Lib "libsodium" () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_pclmul Lib "libsodium" () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_sse2 Lib "libsodium" () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_sse3 Lib "libsodium" () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_sse41 Lib "libsodium" () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_runtime_has_ssse3 Lib "libsodium" () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_version_string Lib "libsodium" () As Ptr
	#tag EndExternalMethod


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
