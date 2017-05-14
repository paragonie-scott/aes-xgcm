# AES-256-XGCM
 
 AES-256-XGCM is AES-256-GCM with an eXtended nonce.
 
 * Nonce size: 352 bits (44 bytes)
 * Key size: 256 bits (32 bytes)
 * Tag size: 256 bits (32 bytes)
 
 Unlike traditional AES-GCM, you don't need to worry about rekeying after a small number of messages.
 The first 256 bits of the nonce are used along with the key to generate a sub-key for AES-GCM. The
 remaining 96 bits of the nonce are used as the AES-GCM nonce.
 
 This was inspired by Xsalsa20 (eXtended-nonce Salsa20).