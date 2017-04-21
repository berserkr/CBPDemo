# -*- coding: utf-8 -*-
"""Security utilities module

Attributes:

Todo:
    * For module TODOs

"""
__author__ = "Luis Bathen"
__copyright__ = "Copyright 2016, IBM"
__credits__ = ["Luis Bathen"]
__license__ = "IBM"
__version__ = "0.1"
__maintainer__ = "Luis Bathen"
__email__ = "bathen@us.ibm.com"
__status__ = "Beta"

from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import randrange_from_seed__trytryagain
from ecdsa.util import PRNG
from bitcoin import *
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.PublicKey import RSA
import hashlib, hmac
import base64
import time, datetime, pytz
import json
from logger import logger
import dateutil.parser
from os import urandom
from binascii import hexlify
from bitcoin import *

def hash_512(data):
    return hashlib.sha512(data).hexdigest()

def hash_256(data):
    return hashlib.sha256(data).hexdigest()

def ecdsa_deterministic_keygen_salty(seed, salt):
    """(seed) -> bip32 master key

    Args:
        a seed string, a salt

    Returns:
        a master key

    Raises:
        None
    """
    ecdsa_seed = hash_256(seed + salt)
    return bip32_master_key(ecdsa_seed), salt

def ecdsa_deterministic_keygen(seed):
    """(seed) -> bip32 master key

    Args:
        a seed string

    Returns:
        a master key

    Raises:
        None
    """
    random_bytes = hexlify(urandom(32))
    salt = base64.urlsafe_b64encode(random_bytes)
    ecdsa_seed = hash_256(seed + salt)
    return bip32_master_key(ecdsa_seed), salt

def ecdsa_get_pub_key(private_key):
    """(private bip32 key) -> public bip32 key -> pub key

    Args:
        a bip32 private key

    Returns:
        a public key

    Raises:
        None
    """
    bip32_pub_key = bip32_privtopub(private_key)
    return bip32_extract_key(bip32_pub_key)

def ecdsa_get_child_key(key, i):
    """(private or public bip32 key, i) -> child key

    Args:
        key, ith number

    Returns:
        ith child key

    Raises:
        None
    """
    return bip32_ckd(key, i)

def sign_message(private_key, message):
    """signs a message with a private key, returns the signature and the public key

    Args:
        message in plain text, a signing key

    Returns:
        signature, verification key in string hex format

    Raises:
        assertion failure if the signature is not verified
    """
    pub = privkey_to_pubkey(private_key)
    sig = ecdsa_sign(message, private_key)
    assert ecdsa_verify(message, sig, pub)

    sig = (base64.b64decode(sig)).encode('hex')
    
    logger.info ('Signature/Ver Key Pair: [%s,%s]' % (sig,
                                                      pub))
    return sig, pub

def verify_message(public_key, message, signature):
    """verify a message

    Args:
        a verification key string (hex), a message, and a signature (hex)

    Returns:
        true if we are able to verify the message, false otherwise

    Raises:
        None
    """
    sig = base64.b64encode(signature.decode('hex'))
    return ecdsa_verify(message, sig, public_key)

def make_key_with_salt(seed, salt):
    """generates a key from a given seed, returns the key and a salt

    Args:
        seed

    Returns:
        signing key, a salt

    Raises:
        assertion failure if the signature is not verified
    """
    ecdsa_seed = hash_256(seed + salt)
    secexp = randrange_from_seed__trytryagain(ecdsa_seed, SECP256k1.order)
    return SigningKey.from_secret_exponent(secexp, curve=SECP256k1), salt

def make_key(seed):
    """generates a key from a given seed, returns the key and a salt

    Args:
        seed

    Returns:
        signing key, a salt

    Raises:
        assertion failure if the signature is not verified
    """
    random_bytes = hexlify(urandom(32))
    salt = base64.urlsafe_b64encode(random_bytes)
    ecdsa_seed = hash_256(seed + salt)
    secexp = randrange_from_seed__trytryagain(ecdsa_seed, SECP256k1.order)
    return SigningKey.from_secret_exponent(secexp, curve=SECP256k1), salt

"""
def sign_message(message):
    ""signs a message with a new key, returns the signature and the priv key

    Args:
        message in plain text

    Returns:
        signature, signing key

    Raises:
        assertion failure if the signature is not verified
    ""

    sk = SigningKey.generate(curve=SECP256k1) # uses NIST192p
    vk = sk.get_verifying_key()
    signature = sk.sign(message)
    assert vk.verify(signature, message)

    return signature, sk

def sign_message(sk, message):
    ""signs a message with a signing key, returns the signature and the verification key

    Args:
        message in plain text, a signing key

    Returns:
        signature, verification key in string hex format

    Raises:
        assertion failure if the signature is not verified
    ""

    vk = sk.get_verifying_key()
    signature = sk.sign(message)
    assert vk.verify(signature, message)

    logger.info ('Signature/Ver Key Pair: [%s,%s]' % (signature.encode('hex'),
                                                      vk.to_string().encode('hex')))
    return signature.encode('hex'), vk.to_string().encode('hex')
"""

def sk_to_vk(sk):
    vk = sk.get_verifying_key()
    return vk.to_string().encode('hex')

def verify_key(sk_string, seed):
    """verifies a key string matches a specific key

    Args:
        a signing key (from_string()), and a string seed

    Returns:
        true if keys match, false otherwise

    Raises:
        None
    """

    sk = generate_key(seed)
    sk2 = SigningKey.from_string(sk_string, curve=SECP256k1)

    # sk and sk2 are the same key
    return sk == sk2
"""
def verify_message(vk_string, message, signature):
    ""verify a message

    Args:
        a verification key string (hex), a message, and a signature (hex)

    Returns:
        true if we are able to verify the message, false otherwise

    Raises:
        None
    ""

    signature = signature.decode('hex')
    vk_string = vk_string.decode('hex')
    vk = VerifyingKey.from_string(vk_string, curve=SECP256k1)
    return vk.verify(signature, message)
"""

def encrypt(key, iv, plain_text):
    """encrypt a plain text message

    Args:
        an encryption key, an IV (salt), and the plain text to encrypt

    Returns:
        an encrypted ciphertext in base64 encoding

    Raises:
        assertion fails if we are unable to decrypt the message with the same key/IV
    """

    # Need to pad the block size to match the expected multiple of 16
    if len(plain_text) % 16 != 0:
        pad_cnt = 16 - (len(plain_text) % 16)
        pad = ''
        for i in range(0, pad_cnt):
            pad += ' '
        plain_text = pad + plain_text

    encryption_suite = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = encryption_suite.encrypt(plain_text)

    """
    print ('Encoded encrypted payload: %s' % base64.urlsafe_b64encode(cipher_text))
    print ('Decoded encrypted payload: %s' % base64.urlsafe_b64decode(base64.urlsafe_b64encode(cipher_text)))
    """

    # Verify that encryption and decryption work...
    plain_text_2 = decrypt(key, iv, base64.urlsafe_b64encode(cipher_text))
    assert plain_text_2 == plain_text

    logger.debug('returning %s' % base64.urlsafe_b64encode(cipher_text))

    # return base64 encoding
    return base64.urlsafe_b64encode(cipher_text)

def encrypt(key, plain_text):
    """encrypt a plain text message

    Args:
        an encryption key, an IV (salt), and the plain text to encrypt

    Returns:
        an encrypted ciphertext in base64 encoding

    Raises:
        assertion fails if we are unable to decrypt the message with the same key/IV
    """
    iv = Random.new().read( AES.block_size )

    # Need to pad the block size to match the expected multiple of 16
    if len(plain_text) % 16 != 0:
        pad_cnt = 16 - (len(plain_text) % 16)
        pad = ''
        for i in range(0, pad_cnt):
            pad += ' '
        plain_text = pad + plain_text

    encryption_suite = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = encryption_suite.encrypt(plain_text)

    # Verify that encryption and decryption work...
    plain_text_2 = decrypt(key, base64.urlsafe_b64encode(iv + cipher_text))
    assert plain_text_2 == plain_text

    logger.debug('returning %s' % base64.urlsafe_b64encode(iv + cipher_text))

    # return base64 encoding
    return base64.urlsafe_b64encode(iv + cipher_text)

def decrypt(key, iv, cipher_text):
    """decrypt a cipher text message

    Args:
        a decryption key, an IV (salt), and the cipher text to decrypt (base64 encoded)

    Returns:
        an encrypted ciphertext in base64 encoding

    Raises:
        None
    """

    # cipher is stored as base64, will decode before decrypting...
    cipher_text = base64.urlsafe_b64decode(cipher_text)
    decryption_suite = AES.new(key, AES.MODE_CBC, iv)
    plain_text = decryption_suite.decrypt(cipher_text)

    return plain_text

def decrypt(key, cipher_text):
    """decrypt a cipher text message

    Args:
        a decryption key, an IV (salt), and the cipher text to decrypt (base64 encoded)

    Returns:
        an encrypted ciphertext in base64 encoding

    Raises:
        None
    """

    # cipher is stored as base64, will decode before decrypting...
    cipher_text = base64.urlsafe_b64decode(cipher_text)
    iv = cipher_text[:16]
    decryption_suite = AES.new(key, AES.MODE_CBC, iv)
    plain_text = decryption_suite.decrypt(cipher_text[16:])

    return plain_text

def generate_key(seed):
    """generate a key from a seed

    Args:
        a seed in plain text

    Returns:
        a signing key

    Raises:
        None
    """

    ring = PRNG(seed)
    sk = SigningKey.generate(entropy=ring, curve=SECP256k1)

    return sk

def create_nonce():
    #st = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
    st = str(time.time())
    nonce = str(Random.new().read( AES.block_size )) + st
    return base64.urlsafe_b64encode(nonce)

"""

RSA Crypto Helper Methods

"""

def create_rsa_key():
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    return key

def rsa_encrypt(key, plain_text):
    """encrypt a plain text message

    Args:
        an rsa public key, a plain text

    Returns:
        an encrypted ciphertext in base64 encoding

    Raises:
        None

    """

    # first convert key so we can use padding
    rsakey = PKCS1_OAEP.new(key)
    cipher_text = rsakey.encrypt(plain_text)
    return cipher_text.encode('base64')

def rsa_decrypt(key, cipher_text):
    """decrypt a cipher text message

    Args:
        an rsa private key, a cipher text (base64 encoded)

    Returns:
        a decrypted plain text

    Raises:
        assert that the key is a private key

    """
    
    assert key.has_private()

    # first conver they key
    rsakey = PKCS1_OAEP.new(key)

    # now decode the data then decrypt it
    plain_text = rsakey.decrypt(base64.urlsafe_b64decode(cipher_text))

    #plain_text = key.decrypt(data)
    return plain_text

def key_to_pem(key):
    return key.exportKey('PEM')

def pem_to_key(pem):
    return RSA.importKey(pem)

def save_pem(pem, fname):
    f = open(fname,'w')
    f.write(pem)
    f.close()

def load_pem(fname):
    f = open(fname,'r')
    pem = f.read()
    return pem

def hmac_sha256(message, secret):
    message_utf8 = bytes(message).encode('utf-8')
    secret_utf8 = bytes(secret).encode('utf-8')
    signature = base64.urlsafe_b64encode(hmac.new(secret_utf8, message_utf8, digestmod=hashlib.sha256).digest())
    return signature

def jwt_encode(header, payload, secret):
    message = base64.urlsafe_b64encode(header) + '.' + base64.urlsafe_b64encode(payload)
    
    if not message:
        return 'Could not generate message', True
    
    signature = hmac_sha256(message, secret)

    if not signature:
        return 'Could not generate signature', True

    return message + '.' + signature, False

def jwt_decode(token, secret):
    items = token.split('.')
    if not items or len(items) < 3:
        logger.error ('Invalid token %s' % token)
        return 'Invalid token %s' % token, True
    
    header = items[0]
    payload = items[1]
    signature = items[2]

    logger.info ('Decoded [%s, %s, %s]' % (header, payload, signature))

    message = header + '.' + payload
    signature2 = hmac_sha256(message, secret)

    if signature != signature2:
        logger.error ('Invalid signature %s != %s' % (signature, signature2))
        return 'Invalid signature %s != %s' % (signature, signature2), True

    current_time = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
    header = json.loads(base64.urlsafe_b64decode(header))
    payload = json.loads(base64.urlsafe_b64decode(payload))

    logger.info ('Header: %s, Payload: %s' % (json.dumps(header), json.dumps(payload)))

    nbf = dateutil.parser.parse(payload['nbf']).replace(tzinfo=pytz.UTC)
    exp = dateutil.parser.parse(payload['exp']).replace(tzinfo=pytz.UTC)

    if current_time < nbf or current_time > exp:
        logger.error ('Token expired %s' % exp)
        return 'Token expired %s' % exp, True

    return payload, False

    

