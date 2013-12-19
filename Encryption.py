from Crypto.Cipher import AES
from Crypto import Random
import base64
import hashlib
import hmac

class AESEncrypt:
    
    BLOCK_SIZE = 16
    PADDING = '\0'
    
    def __init__(self):
        self.key = Random.new().read(self.BLOCK_SIZE)
    
    def encrypt(self, message):
        iv = Random.new().read(self.BLOCK_SIZE)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = base64.b64encode(iv + cipher.encrypt(self.pad(message)))
        digest = self.get_hmac(ciphertext)
        return str(digest) + str(ciphertext)


    def decrypt(self, ciphertext):
        digest = ciphertext[:16]
        ciphertext = ciphertext[16:]
        if str(digest) != str(self.get_hmac(ciphertext)):
            print("[-] MESSAGE TAMPERED")
        iv = base64.b64decode(ciphertext)[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return cipher.decrypt(base64.b64decode(ciphertext)[16:])\
        .rstrip(self.PADDING)
                    

    def get_hmac(self, message):
        key = hashlib.sha1(self.key).digest()
        digest = hmac.new(key, message, hashlib.sha512).digest()
        return base64.b64encode(digest)[:16]


    def pad(self, message):
        return message + (self.BLOCK_SIZE - len(message) % self.BLOCK_SIZE) * \
        self.PADDING