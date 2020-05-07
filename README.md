# PKCS11 bindings for PHP

Work in progress. DO NOT USE!

Currently supports:

* C_Initialize (via new PKCS11\Module())
* C_GetInfo
* C_GetSlotList
* C_GetSlotInfo
* C_GetTokenInfo
* C_InitToken
* C_GetMechanismList
* C_GetMechanismInfo
* C_OpenSession
* C_Login
* C_Logout
* C_InitPIN
* C_SetPIN
* C_GenerateKey
* C_GenerateKeyPair
* C_FindObjectsInit
* C_FindObjects
* C_FindObjectsFinal
* C_EncryptInit
* C_Encrypt
* C_DecryptInit
* C_Decrypt
* C_SignInit
* C_Sign
* Reading object attributes, including public key attributes

Coming up in (probable) order:
* PSS Signature
* ECDSA Signature
* C_WrapKey
* C_UnwrapKey
* C_DeriveKey

