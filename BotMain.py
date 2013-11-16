from Crypto.Cipher import AES
from Crypto import Random
import subprocess
import base64
import hashlib
import hmac
import socket
import urllib
import time
import sys
import os

class Bot:

	BLOCK_SIZE = 16
	PADDING = '\0'
	IRC = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	def __init__(self, server, channel,port):
			# Connection Information
			self.server = server
			self.channel = channel
			self.port = port


	def connect(self, nick, userid):
		self.IRC.connect((self.server, self.port))
		self.IRC.send('NICK %s%i\r\n' % (nick, userid))
		self.IRC.send('USER %i 8 * :%s\r\n' % (userid, nick))
		time.sleep(4)
		self.IRC.send('JOIN %s\r\n' % (self.channel))

	def encryptAES(self, message, key):
		iv = Random.new().read(self.BLOCK_SIZE)
		cipher = AES.new(key, AES.MODE_CBC, iv)
		ciphertext = base64.b64encode(iv + cipher.encrypt(self.pad(message)))
		digest = self.get_hmac(ciphertext, key)
		return str(digest) + str(ciphertext)


	def decryptAES(self, ciphertext, key):
		digest = ciphertext[:16]
		ciphertext = ciphertext[16:]
		if str(digest) != str(self.get_hmac(ciphertext,key)):
			print "MESSAGE TAMPERED"
		iv = base64.b64decode(ciphertext)[:16]
		cipher = AES.new(key, AES.MODE_CBC, iv)
		return cipher.decrypt(base64.b64decode(ciphertext)[16:]).rstrip(self.PADDING)
					

	def get_hmac(self, message, key):
		digest = hmac.new(key, message, hashlib.sha512).digest()
		return base64.b64encode(digest)[:16]

	def pad(self, message):
		return message + (self.BLOCK_SIZE - len(message) % self.BLOCK_SIZE) * \
		self.PADDING

	def get_ip_location(self, ip):
		return urllib.urlopen('http://api.hostip.info/get_html.php?ip='+ip+\
			'&position=true').read()

	def get_active_connections(self):
		cmd = "sudo netstat -alpn | grep :80 | awk '{print $5}' |awk -F: "\
		"'{print $(NF-1)}' |sort | uniq -c | sort -n"
		ps =  subprocess.Popen(cmd, stdout=subprocess.PIPE, \
			stderr=subprocess.STDOUT, shell=True)
		return ps.communicate()[0]
