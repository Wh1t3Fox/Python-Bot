#!/usr/bin/env python
from Messaging import Message, socket
import nmap
import subprocess
import urllib

class Bot(Message):
        
    def __init__(self):
        Message.__init__(self)
        self.port = '9999'


    def connect(self, serv, portNum):
        Message.SERVER.connect((serv, int(portNum)))
        while True:
            data = Message.SERVER.recv(1024)
            print data
            if data.find('QUIT') != -1:
                break


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
        open_hosts = []
        closed_hosts = []
        nm = nmap.PortScanner()
        ip_range = self.get_local_ip()[:-2] + '.0/24'
        
        nm.scan(hosts=ip_range, arguments='-n -PN -PA'+self.port)
        for host in nm.all_hosts():
            try:
                if nm[host]['tcp'][int(self.port)]['state'] == 'open':
                    open_hosts.append(host)
                else:
                    closed_hosts.append(host)
            except:
                closed_hosts.append(host)
        print open_hosts
        print "\n"
        print closed_hosts
                
bot = Bot()
bot.scan_network()