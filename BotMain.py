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
    port = '9999'
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
        s.connect(("google.com",80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    
    def callback_result(self, host, scan_result):
        try:
            if scan_result['scan'][unicode(host)]['tcp'][int(self.port)]['state'] == 'open':
                print("%s \tOPEN" % host)
                #self.connect(host, self.port)
            else:
                print("%s \tClosed" % host)
        except:
            print("%s \tClosed" % host)
    
    def scan_network(self):
        nm = nmap.PortScannerAsync()
        ip_range = self.get_local_ip()[:-2] + '.1-20'
        
        nm.scan(hosts=ip_range, arguments='-n -PN -PA'+self.port, callback=self.callback_result)
        while nm.still_scanning():
            nm.wait(2)
                

bot = Bot()