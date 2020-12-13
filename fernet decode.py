import base64
import binascii

import struct
import time
import six
_MAX_CLOCK_SKEW = 60

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.fernet import Fernet

import sys

token = "Du40w_rKyOddjj_Yj7swQ3tvj8mP4e9ucqjK8TPRNUZEnV2h21hNpTkENMbsIsjoGDq8OuqxGg650DW0Q3PCn_3zQtvzuVEHkskELlylSNJksUqS_sl5NXr2IE_5q7RUpbBnU6cp0bSVDfAHcuIsngJJnfwsvuEDseDSRgkBIqc0hrLOvC3AvJATHrYC9HWreJKVwh79yaYigcPeKHeiVsFTfijxRd3TnrDLPG6SChVMtmt4JZYsBF7s8xbMr4-ACOdAAorW3CSaQW8POBNN-sv36I5SZHqNCsrvuZ1GwvtFBL08GvQe_jyXqlLRI7h8qAPk1yUtKRgRRC0bzZWkx4v5DZGieKwxUgj7HdK4_GmJmo4mU=";
key= "wROoxeKUr4z7TwAEPXCIoOSoNs7Ctjvw=";

if (len(sys.argv)>1):
	token=sys.argv[1]

if (len(sys.argv)>2):
	key=sys.argv[2]

def decrypt(self, token, ttl=None):
  current_time = int(time.time())
  print("Current time:\t",time.ctime(current_time))

  print("\nToken Details")
  print("=============")
  if not isinstance(token, bytes):
    raise TypeError("token must be bytes.")




  try:
    data = base64.urlsafe_b64decode(token)
  except (TypeError, binascii.Error):
    raise InvalidToken

  print("Decoded data: ",binascii.hexlify(bytearray(data)))

  print("======Analysis====")

  print("Version:\t",binascii.hexlify(bytearray(data[0:1])))

  print("Date created:\t",binascii.hexlify(bytearray(data[1:9])))

  print("IV:\t\t",binascii.hexlify(bytearray(data[9:25])))

  print("Cipher:\t\t",binascii.hexlify(bytearray(data[25:-32])))

  print("HMAC:\t\t",binascii.hexlify(bytearray(data[-32:])))

  print("======Converted====")

  if not data or six.indexbytes(data, 0) != 0x80:
    raise InvalidToken

  try:
    timestamp, = struct.unpack(">Q", data[1:9])
    print("Time stamp:\t",timestamp)
    print("Date created:\t",time.ctime(timestamp))
  
  except struct.error:
    raise InvalidToken

  if ttl is not None:
    if timestamp + ttl < current_time:
      raise InvalidToken
    if current_time + _MAX_CLOCK_SKEW < timestamp:
      raise InvalidToken


  h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
  h.update(data[:-32])

  try:
    h.verify(data[-32:])
  except InvalidSignature:
    raise InvalidToken

  iv = data[9:25]
  print("IV:\t\t",binascii.hexlify(iv))

  ciphertext = data[25:-32]
  decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).decryptor()
  plaintext_padded = decryptor.update(ciphertext)
  try:
    plaintext_padded += decryptor.finalize()
  except ValueError:
    raise InvalidToken
  unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

  unpadded = unpadder.update(plaintext_padded)
  try:
    unpadded += unpadder.finalize()
  except ValueError:
    raise InvalidToken
  print("Decoded:\t",unpadded)
  return unpadded


key
f = Fernet(key)
decrypt(f,token.encode())