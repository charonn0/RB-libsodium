#tag Class
Protected Class MasterKey
Inherits libsodium.SKI.KeyContainer
	#tag Method, Flags = &h1000
		Sub Constructor()
		  If Not System.IsFunctionAvailable("sodium_kdf_keygen", "libsodium") Then Raise New SodiumException(ERR_UNAVAILABLE)
		  Dim mb As New MemoryBlock(crypto_kdf_KEYBYTES)
		  crypto_kdf_keygen(mb)
		  Me.Constructor(mb)
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1001
		Protected Sub Constructor(KeyData As MemoryBlock)
		  // Calling the overridden superclass constructor.
		  CheckSize(KeyData, crypto_kdf_KEYBYTES)
		  Super.Constructor(KeyData)
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function DeriveKey(KeyLength As Int32, SubkeyID As UInt64, Context As MemoryBlock) As MemoryBlock
		  If Not System.IsFunctionAvailable("crypto_kdf_derive_from_key", "libsodium") Then Raise New SodiumException(ERR_UNAVAILABLE)
		  CheckSize(Context, crypto_kdf_CONTEXTBYTES)
		  Dim subkey As New MemoryBlock(KeyLength)
		  If crypto_kdf_derive_from_key(subkey, subkey.Size, SubkeyID, Context, Me.Value) <> 0 Then
		    Raise New SodiumException(ERR_COMPUTATION_FAILED)
		  End If
		  Return subkey
		End Function
	#tag EndMethod


	#tag Constant, Name = crypto_kdf_CONTEXTBYTES, Type = Double, Dynamic = False, Default = \"8", Scope = Public
	#tag EndConstant

	#tag Constant, Name = crypto_kdf_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Protected
	#tag EndConstant


End Class
#tag EndClass
