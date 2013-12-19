from Encryption import AESEncrypt
import socket

class Message(AESEncrypt):
    
    SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def __init__(self):
        AESEncrypt.__init__(self)
    
    def send_message(self, message):
        self.SERVER.sendall(AESEncrypt.encrypt(message))


    def receive_message(self, ciphertext):
        return AESEncrypt.decrypt(ciphertext)