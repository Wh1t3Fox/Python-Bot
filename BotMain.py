import socket
import time

class Bot:


	def __init__(self, server, channel,port):
			self.server = server
			self.channel = channel
			self.port = port
			self.irc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	def connect(self, nick, userid):
		self.irc.connect((self.server, self.port))
		self.irc.send('NICK %s%i\r\n' % (nick, userid))
		self.irc.send('USER %i 8 * :%s\r\n' % (userid, nick))
		time.sleep(4)
		self.irc.send('JOIN %s\r\n' % (self.channel))
		

	def return_values(self):
		print "Server: %s" % (self.server)
		print "Channel: %s" % (self.channel)
		print "Port: %s" % (self.port)