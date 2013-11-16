from Crypto.Cipher import AES
import base64
import socket
import time
import os

class Bot:

	def __init__(self, server, channel,port):
			# Connection Information
			self.server = server
			self.channel = channel
			self.port = port
			self.IRC = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

			#Cryptographic Setup
			self.BLOCK_SIZE = 16
			self.PADDING = '\0'


	def connect(self, nick, userid):
		self.IRC.connect((self.server, self.port))
		self.IRC.send('NICK %s%i\r\n' % (nick, userid))
		self.IRC.send('USER %i 8 * :%s\r\n' % (userid, nick))
		time.sleep(4)
		self.IRC.send('JOIN %s\r\n' % (self.channel))

	def encryptAES(self, message, key):
		cipher = AES.new(key)
		return base64.b64encode(cipher.encrypt(self.pad(message)))


	def decryptAES(self, ciphertext, key):
		cipher = AES.new(key)
		return cipher.decrypt(base64.b64decode(ciphertext)).rstrip(self.PADDING)


	def pad(self, message):
		return message + (self.BLOCK_SIZE - len(message) % self.BLOCK_SIZE) * \
		self.PADDING


	def return_values(self):
		print "Server: %s" % (self.server)
		print "Channel: %s" % (self.channel)
		print "Port: %s" % (self.port)