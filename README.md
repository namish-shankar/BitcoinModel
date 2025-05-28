BitcoinModel
-----------------------------------------------------------------------------------------------------------------------


this Python script shows how you can:

1. Take a raw Bitcoin transaction and make a TXID out of it
2. Sign it using ECDSA (that elliptic curve thing Bitcoin uses)
3. Check if the signature is valid
4. Try to get the public key back from just the signature and message

It uses algos like SHA256, secp256k1, and RFC6979 (which makes sure we don’t reuse nonces). 


Project Structure
-----------------------------------------------------------------------------------------------------------------------

1. Dependencies:
   1-> I used hashlib and hmac for the hashing and secure keys
   2-> ecdsa lib handles all the elliptic curve things (curve used is secp256k1 like Bitcoin)

2. Transaction Hashing:
   There’s a function called create_tx_hash(tx_data: bytes) -> str  
   It applies SHA256 two times to the transaction and flips it (little endian style)

3. Transaction Signing:
   Function: sign_transaction(private_key: int, tx_hash: bytes)
   - Makes a deterministic signature using ECDSA and RFC ...
   - Uses low-S normalization (that just means it avoids malleability issues)
   - Gives back a (r, s) tuple as signature

4. Signature Verification:
   Function: verify_signature(pubkey: bytes, sig: tuple, tx_hash: bytes)
   - It puts the (r,s) values back into DER format and checks it
   - If signature matches, returns true.

5. Public Key Recovery:
   Function: recover_public_key(sig: tuple, tx_hash: bytes)
   - Tries to get back the public key just from the signature and hash
   - Loops through the 4 possible answers ...
   - Sometimes useful in Bitcoin stuff like signature validation without public key

6. Helper Functions: 
   1-> _rfc6979_nonce: Makes sure each signature uses a different k (very important)
   
   2-> _der_sig_encode and decode: used to convert signature to/from DER format
   
   3-> _int_to_bytes: converts integers into byte strings (needed for DER)

---

Example Flow:


txid = create_tx_hash(tx_data)

signature = sign_transaction(private_key, tx_hash)     

valid = verify_signature(pubkey, signature, tx_hash)






