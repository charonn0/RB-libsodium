#tag Class
Protected Class SecureMemory
	#tag Method, Flags = &h1
		Protected Sub Constructor()
		  If sodium_init() = -1 Then Raise New SodiumException("libsodium could not be initialized.")
		End Sub
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mProtectionLevel As libsodium.MemoryProtectionLevel = libsodium.MemoryProtectionLevel.ReadWrite
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mPtr As Ptr
	#tag EndProperty

	#tag ComputedProperty, Flags = &h0
		#tag Getter
			Get
			  return mProtectionLevel
			End Get
		#tag EndGetter
		#tag Setter
			Set
			  Dim i As Integer
			  Select Case value
			  Case libsodium.MemoryProtectionLevel.ReadWrite
			    i = sodium_mprotect_readwrite(mPtr)
			  Case libsodium.MemoryProtectionLevel.ReadOnly
			    i = sodium_mprotect_readonly(mPtr)
			  Case libsodium.MemoryProtectionLevel.NoAccess
			    i = sodium_mprotect_noaccess(mPtr)
			  End Select
			  If i = -1 Then Raise New SodiumException("Unable to set the memory protection level.")
			  mProtectionLevel = value
			End Set
		#tag EndSetter
		ProtectionLevel As libsodium.MemoryProtectionLevel
	#tag EndComputedProperty


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
