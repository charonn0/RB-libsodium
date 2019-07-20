#tag Class
Protected Class SodiumException
Inherits RuntimeException
	#tag Method, Flags = &h0
		Sub Constructor(ErrorCode As Int32)
		  Me.ErrorNumber = ErrorCode
		  Select Case ErrorCode
		  Case ERR_INIT_FAILED
		    Me.Message = "libsodium cannot be initialized."
		    
		  Case ERR_UNAVAILABLE
		    Me.Message = "libsodium is not installed."
		    
		  Case ERR_FUNCTION_UNAVAILABLE
		    Me.Message = "This version of libsodium does not export the requested function."
		    
		  Case ERR_PROTECT_FAILED
		    Me.Message = "Unable to set the protection level for the specified memory range."
		    
		  Case ERR_CANT_ALLOC
		    Me.Message = "Unable to create a buffer of the requested size."
		    
		  Case ERR_TOO_LARGE
		    Me.Message = "The data are too large for the buffer."
		    
		  Case ERR_READ_DENIED
		    Me.Message = "The specified memory range is secured and cannot be accessed."
		    
		  Case ERR_WRITE_DENIED
		    Me.Message = "The specified memory range is secured and cannot be modified."
		    
		  Case ERR_LOCK_DENIED
		    Me.Message = "The specified memory lock cannot be modified."
		    
		  Case ERR_INVALID_STATE
		    Me.Message = "The requested operation is illegal in the current context."
		    
		  Case ERR_COMPUTATION_FAILED
		    Me.Message = "The requested operation failed, possibly due to resource limits."
		    
		  Case ERR_SIZE_MISMATCH
		    Me.Message = "The requested operation expected input of a different length than what was provided."
		    
		  Case ERR_KEYGEN_FAILED
		    Me.Message = "Generating a cryptographic key pair failed."
		    
		  Case ERR_KEYDERIVE_FAILED
		    Me.Message = "Deriving a cryptographic key failed."
		    
		  Case ERR_OPSLIMIT
		    Me.Message = "The OpsLimit parameter must be greater-than or equal-to 3."
		    
		  Case ERR_OUT_OF_RANGE
		    Me.Message = "A parameter is invalid because it is outside the expected range."
		    
		  Case ERR_CONVERSION_FAILED
		    Me.Message = "The requested key-type conversion failed."
		    
		  Case ERR_IMPORT_PASSWORD
		    Me.Message = "The given password does not decrypt this exported key."
		    
		  Case ERR_IMPORT_ENCRYPTED
		    Me.Message = "This exported key is password protected but no password was provided."
		    
		  Case ERR_WRONG_HALF
		    Me.Message = "The ForeignKey class may not be used with the secret half of keypairs."
		    
		  Case ERR_OUT_OF_BOUNDS
		    Me.Message = "The requested operation failed because it would have exceeded an allocation boundary."
		    
		  Case ERR_SIZE_REQUIRED
		    Me.Message = "The requested operation cannot be performed on MemoryBlocks of unknown size."
		    
		  Case ERR_KEYTYPE_MISMATCH
		    Me.Message = "The specified key is of a type that is not intended for the requested operation."
		    
		  Case ERR_PARAMETER_CONFLICT
		    Me.Message = "Two or more parameters are mutually contradictory."
		    
		  Case ERR_IMPORT_INVALID
		    Me.Message = "The data do not conform to the export format."
		    
		  Case ERR_PADDING
		    Me.Message = "Error while padding or unpadding data."
		    
		  Case ERR_DECRYPT_FAIL
		    Me.Message = "Decryption or authentication failed."
		    
		  Else
		    Me.Message = "Unknown error in libsodium."
		    
		  End Select
		End Sub
	#tag EndMethod


	#tag ViewBehavior
		#tag ViewProperty
			Name="ErrorNumber"
			Group="Behavior"
			InitialValue="0"
			Type="Integer"
			InheritedFrom="RuntimeException"
		#tag EndViewProperty
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
			Name="Message"
			Group="Behavior"
			Type="String"
			EditorType="MultiLineEditor"
			InheritedFrom="RuntimeException"
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
