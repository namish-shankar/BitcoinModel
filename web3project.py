#web3 project 

import hashlib
import hmac
#Hash-based Message Authentication Code. It combines a cryptographic hash function (like SHA-256) with a secret key, making it resistant to tampering.

from ecdsa import SECP256k1, SigningKey, VerifyingKey, util
#secp256k1 isecp256k1 is a specific elliptic curve(its a Koblitz curve)->defined over prime field(prime field me all operations done modulo p and evrey no has a multiplicaitve inverse

from ecdsa.util import number_to_string
# Example raw transaction data (bytes)

#a sample transaction data(asked chatgpt to generate one TXID)
tx_data = bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d014dffffffff0100f2052a01000000434104e70a02f5af48a1989bf630d92523c9d14c45c75f7d1b998e962bff6ff9995fc5bdb44f1793b37495d80324acba7c8f537caaf8432b8d47987313060cc82d8a93ac00000000')
#print(tx_data)


'''
after decoding this TXID on 'BLOCKCYPHER'software, I got its JSON as :
{
    "addresses": [
        "13A1W4jLPP75pzvn2qJ5KyyqG3qPSpb9jM"
    ],
    "block_height": -1,
    "block_index": -1,
    "confirmations": 0,
    "double_spend": false,
    "fees": 0,
    "hash": "2d05f0c9c3e1c226e63b5fac240137687544cf631cd616fd34fd188fc9020866",
    "inputs": [
        {
            "age": 0,
            "output_index": -1,
            "script": "04ffff001d014d",
            "script_type": "empty",
            "sequence": 4294967295
        }
    ],
    "outputs": [
        {
            "addresses": [
                "13A1W4jLPP75pzvn2qJ5KyyqG3qPSpb9jM"
            ],
            "script": "4104e70a02f5af48a1989bf630d92523c9d14c45c75f7d1b998e962bff6ff9995fc5bdb44f1793b37495d80324acba7c8f537caaf8432b8d47987313060cc82d8a93ac",
            "script_type": "pay-to-pubkey",
            "value": 5000000000
        }
    ],
    "preference": "low",
    "received": "2025-05-23T08:56:55.373754893Z",
    "relayed_by": "3.235.47.237",
    "size": 134,
    "total": 5000000000,
    "ver": 1,
    "vin_sz": 1,
    "vout_sz": 1,
    "vsize": 134
}
'''


def create_tx_hash(tx_data: bytes) -> str:
    """
    to generate txid using sha256
    
    returns txid as a hexadecimal string, in little-endian format (convetional)->least significant bigts first

   notes:
    TXID: A unique identifier for a Bitcoin transaction, created by hashing the transaction data.
    'Double' SHA-256: The process of hashing data twice with the SHA-256 algorithm, as used by Bitcoin.
       
    """
#double hashing
    fhsh = hashlib.sha256(tx_data).digest()
    txid_hash = hashlib.sha256(fhsh).digest()
    
    # reverse to convert from bigendian (return type of sha256) to littlendian
    return txid_hash[::-1].hex()


#---------------------------------------

#ai generated private key for sample
private_key = 0x1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd 
tx_hash = bytes.fromhex('c3e3a7c6b3c5e8c9a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9') 


def sign_transaction(private_key: int, tx_hash: bytes) -> tuple :
    """
    Signs a transaction hash using ECDSA with nonce reuse protection.


        private_key: The private key as an integer.
        tx_hash: The SHA-256 hash of the transaction to be signed.

    
        returns the ecdsa signature as a tuple of ints: (r, s) -> sign confirms that we have the private key without actually shairng the pvt key
        A verifier uses (r, s), the message hash, and the public key to check if the signature is valid using ecdsa verification formulas.

   notes:
    ECDSA: Elliptic Curve Digital Signature Algorithm, the cryptographic scheme used by Bitcoin.
    nonce: A random value used only once in cryptographic operations. Deterministic nonce generation (RFC 6979) prevents reuse.
    Low-S normalization: Adjusting the signature to use the smallther possible value of 's' to prevent signature malleability.

    maths behind this is that:
    r = (k * G).x mod n  
    s = k⁻¹(z + r * d) mod n
    Private key d
    Message hash z
    here n is order of elliptic curve (ecdsa)
    (r,s) ki jagah (r, -smod n) works too . So s should be as far away from n/2 as possible so that it is not easy to copy the signautre by taking -s mod n.....
    """
    sk = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
    
#RFC 6979 deterministic nonce generation. Standard ecdsa requires a new random nonce k for each signature.
    nonce = _rfc6979_nonce(sk, tx_hash)
    #rfc6979 just helps to generate a nonce for each signature 

    
#to create signature with low-S requirement
    sig = sk.sign_digest_deterministic(tx_hash,sigencode=_der_sig_encode,hashfunc=hashlib.sha256)
    
#Parse DER (distinguished encodign rules,binary coding that ensures a given data has a single pssible encoding) to (r,s) 
    return _der_sig_decode(sig)


#================================



#public key from private key for sample case
sk = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
pubkey = sk.get_verifying_key().to_string()


# a tuple sign.
sig = (1234567890123456789012345678901234567890123456789012345678901234, 9876543210987654321098765432109876543210987654321098765432109876)
#tx_hash = bytes.fromhex('c3e3a7c6b3c5e8c9a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9')

def verify_signature(pubkey: bytes, sig: tuple, tx_hash: bytes) -> bool:
    """
    verifies signature using public key recovery.(the ability to reconstruct the public key from a signature and message hash )
        not that Bitcoin enforces specific rules for DER encoding to prevent signature malleability.
    """
    try:
        vk = VerifyingKey.from_string(pubkey, curve=SECP256k1)
        #makes to DER format(reverse of what we parsed DER to(r,s)
        der_sig = _der_sig_encode(sig[0], sig[1], vk.pubkey.order())  # <-- Added line
        der_sig = _der_sig_encode(sig[0], sig[1], vk.pubkey.order())
        return vk.verify_digest(der_sig, tx_hash, sigdecode=_der_sig_decode, hashfunc=hashlib.sha256)

    except Exception as e:
        return False
#====================================================



def recover_public_key(sig: tuple, tx_hash: bytes) -> bytes:
    """
    Recovers a public key from signature and message hash.
    return type is bytes because public key is returned as bytes
    """
    r, s = sig
    curve = SECP256k1

    #genereaotr is the base point of the curve
    generator = curve.generator
    #order of the curve
    order = generator.order()
    
    for i in range(0, 4): #there can be 4 possible public keys from a given signature
        try:
            #for ephermal point R=k*G(G->generator, k->random val(nonce))
            #R is an (x, y) point on the curve ->r is R.x ,ie x coordinate of R
            #for each x there may be two valid y values->i//2 handles it(r=R.x mod n)
            point = util.number_to_point(curve.curve, r + (i//2)*order)
            print(point)
            vk = VerifyingKey.from_public_point(point, curve=SECP256k1)
            print(pk)
            if vk.verify_digest(util.sigencode_der(r, s, order), tx_hash, sigdecode=util.sigdecode_der):
                return vk.to_string()
        except Exception:
            continue
    raise ValueError("Unable to recover public key")

#______________________________________________________________________________________________


#OTHER FXNS

#a simplified version of rfc6979
def _rfc6979_nonce(sk: SigningKey, msg_hash: bytes) -> int:
    """
    RFC 6979 deterministic nonce generation for ECDSA.
    Prevents nonce reuse by deriving a unique nonce from the private key and message hash.
    """
    order = sk.curve.generator.order()
    x = sk.privkey.secret_multiplier
    k = b'\x00' * 32
    v = b'\x01' * 32
    
    msg_hash = number_to_string(int.from_bytes(msg_hash, 'big'), order)
    key = x.to_bytes(32, 'big') + msg_hash
    k = hmac.new(k, v + b'\x00' + key, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b'\x01' + key, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    #.DIGEST SE BYTES RETURN HOTI
    
    return int.from_bytes(v, 'big') % order


#-------------------------------------------------------------------------------

def _der_sig_encode(r: int, s: int, order: int) -> bytes:
    """
    Encodes (r, s) signature components into DER format with low-S normalization.
    """

    #low s for better authenticity
    if s > order // 2: 
        s = order - s
    
    r_bytes = _int_to_bytes(r)
    s_bytes = _int_to_bytes(s)
    
    return (b'\x30' +  bytes([4 + len(r_bytes) + len(s_bytes)]) + b'\x02' + bytes([len(r_bytes)]) + r_bytes +  b'\x02' + bytes([len(s_bytes)]) + s_bytes    )


''' 
for reference:
DER signature looks like:
0x30 | total_len | 0x02 | len(r) | r_bytes | 0x02 | len(s) | s_bytes

'''

def _der_sig_decode(sig: bytes) -> tuple:
    """
    Parses a DER-encoded signature into (r, s) integers.
    """
    if sig[0] != 0x30:
        raise ValueError("Invalid DER signature")
    
    seq_len = sig[1]
    if seq_len != len(sig) - 2:
        raise ValueError("Invalid length byte")
    
    # Parse R
    r_tag = sig[2]
    if r_tag != 0x02:
        raise ValueError("Expected INTEGER tag for R")
    r_len = sig[3]
    r = int.from_bytes(sig[4:4+r_len], 'big')
    
    # Parse S
    s_pos = 4 + r_len
    s_tag = sig[s_pos]
    if s_tag != 0x02:
        raise ValueError("Expected INTEGER tag for S")
    s_len = sig[s_pos+1]
    s = int.from_bytes(sig[s_pos+2:s_pos+2+s_len], 'big')
    
    return (r, s)


#--------------------------------------------------------------------

def _int_to_bytes(num: int) -> bytes:
    """
    Converts an integer to DER-compatible bytes.
    Adds a leading zero if the most significant bit is set.
    """
    unsigned = num.to_bytes((num.bit_length() + 7) // 8, 'big') #(in big endian)
    return b'\x00' + unsigned if unsigned[0] & 0x80 else unsigned #should be positve(forced)



#--------------------execute----------------------------

txid = create_tx_hash(tx_data)
print(" this is transaction id")
print(txid)

signature = sign_transaction(private_key, tx_hash)
print("\n this is signature")
print(signature)

valid = verify_signature(pubkey, sig, tx_hash)
print("\n but is the signature even valid?")
print(valid)






"""    
by NAMISH SHANKAR SRIVASTAVA
24075101
CSE (BTech)
"""
