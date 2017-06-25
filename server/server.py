#!/usr/bin/python
# -*- coding:utf-8 -*-
import socket	#socket
import os
import threading, getopt, sys, string

MAXBUFF = 2048

opts, args = getopt.getopt(sys.argv[1:], "hp:l:",["help","port=","list="])

HOST = '127.0.0.1'	#localhost
PORT = 8002
ADDR=(HOST, PORT)
MAXCONN = 50

for op,value in opts:
	if op in ("-l", "--list"):
		MAXCONN = string.atol(value)
	elif op in ("-p","--port"):
		PORT = string.atol(value)
	elif op in ("-h"):
		usage()
		sys.exit()
		
def usage():
	print """
	-h --help             print the help
    -l --list             Maximum number of connections
    -p --port             To monitor the port number 
	"""

def Login(client, address):
	# client.settimeout(500)
	while 1:
		try:
			buf = client.recv(MAXBUFF)
		except:
			client.close()
		if not buf or buf == "q":
			print address, ' close the connect'
			break
		print 'Received:', buf, 'from', address
		client.send(buf)
	client.close()	

if __name__ == '__main__':
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.bind(ADDR)		#server ip 
	s.listen(MAXCONN)
	print 'Listening at', s.getsockname()
	
	while True:
		client, address = s.accept()
		print 'Connected by', address
		thread = threading.Thread(target=Login, args=(client, address))
		print 'This connection is in the Thread', thread.getName()
		thread.start()
