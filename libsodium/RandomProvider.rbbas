#tag Class
Protected Class RandomProvider
	#tag Method, Flags = &h0
		Sub Close()
		  ' Deallocates the global resources used by the pseudo-random number generator. More specifically, when 
		  ' the /dev/urandom device is used, it closes the descriptor. Explicitly calling this function is almost 
		  ' never required.
		  
		  Call randombytes_close()
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor()
		  If Not mInitialized Then
		    If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		    mName = CUSTOM_PROVIDER_NAME
		    mImplementation.RandomInt = AddressOf RandomUIntCallback
		    mImplementation.Stir = AddressOf RandomStirCallback
		    mImplementation.UnformInt = AddressOf RandomUIntUniformCallback
		    mImplementation.GenRandom = AddressOf RandomBytesCallback
		    mImplementation.CloseFunc = AddressOf RandomClose
		    mImplementation.Name = mName
		    If randombytes_set_implementation(mImplementation) <> 0 Then
		      Raise New SodiumException(ERR_BAD_RANDOM)
		    End If
		    mInitialized = True
		  End If
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Shared Sub RandomBytesCallback(Buffer As MemoryBlock, Size As UInt64)
		  #pragma X86CallingConvention StdCall
		  Break
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Shared Function RandomClose() As Int32
		  #pragma X86CallingConvention StdCall
		  Break
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Shared Sub RandomStirCallback()
		  #pragma X86CallingConvention StdCall
		  Break
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Shared Function RandomUIntCallback() As UInt32
		  #pragma X86CallingConvention StdCall
		  Break
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Shared Function RandomUIntUniformCallback(Upperbound As UInt32) As UInt32
		  #pragma X86CallingConvention StdCall
		  Break
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Stir()
		  ' Reseeds the pseudo-random number generator, if it supports this operation. Calling this function is not 
		  ' required with the default generator, even after a fork() call, unless the descriptor for /dev/urandom was 
		  ' closed using randombytes_close().
		  ' If a non-default implementation is being used (see randombytes_set_implementation()), randombytes_stir() 
		  ' must be called by the child after a fork() call.
		  
		  randombytes_stir()
		End Sub
	#tag EndMethod


	#tag Property, Flags = &h21
		Private Shared mImplementation As randombytes_implementation
	#tag EndProperty

	#tag Property, Flags = &h21
		Private Shared mInitialized As Boolean
	#tag EndProperty

	#tag Property, Flags = &h21
		Private Shared mName As MemoryBlock
	#tag EndProperty


	#tag Constant, Name = CUSTOM_PROVIDER_NAME, Type = String, Dynamic = False, Default = \"CustomRandomImplementation", Scope = Public
	#tag EndConstant


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
