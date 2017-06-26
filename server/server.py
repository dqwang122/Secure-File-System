#!/usr/bin/python
# -*- coding:utf-8 -*-
import socket	#socket
import SocketServer
import os
import threading, getopt, sys, string
import json

sys.path.insert(0, '../')

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto import Random

from error import *
from server_operations import * 

# socket connection settings
HOST = '127.0.0.1'	
PORT = 8001
MAXCONN = 50
MAXBUFF = 2048
servername= 'Secure-File-System-Server'
s_conn = None 
opts, args = getopt.getopt(sys.argv[1:], "hp:l:",["help","port=","list="])

# Crypto settings
RSA_KEY_SIZE = 2048
SERVER_PK = None
SERVER_PRK = None
users = {}
files = {}
home_acls = {}

# file system
ROOT = "./_init_"
SERVER_ROOT = os.path.join(os.environ['HOME'], 'SFS_server')

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
	
def _InitServer():
	SERVER_PRK = RSA.generate(RSA_KEY_SIZE)
	SERVER_PK = SERVER_PRK.publickey()
	f = open(os.path.join(ROOT, "server_pk.pem"), 'w')
	f.write(SERVER_PK.exportKey('PEM'))
	f.close()
	f = open(os.path.join(ROOT, "server_prk.pem"), 'w')
	f.write(SERVER_PRK.exportKey('PEM'))
	f.close()
	# TODO: Init the mysql

def CheckInitSet():
	PK_file = os.path.join(ROOT, "server_pk.pem")
	PRK_file = os.path.join(ROOT, "server_prk.pem")
	if not os.path.exists(PRK_file) or not os.path.exists(PK_file):
		return ServerInit_ERR
	else:
		f = open(PK_file)
		SERVER_PK = RSA.importKey(f.read())
		f.close()
		f = open(PRK_file)
		SERVER_PRK = RSA.importKey(f.read())
		f.close()	
	# TODO: Connect to the mysql
	
	return True
		
def _GetUSERS():
	# TODO
	return True

def _GETFILES():
	# TODO
	return True

def _GETACLS():
	# TODO
	return True
	
def handle_request(argvs)：
	try:
		cmd = argvs["cmd"]
		if cmd == "register":
			Unfinish()
		elif cmd == "Login":
			Unfinish()
		elif cmd == "cd":
			Unfinish()
		elif cmd == "pwd":
			# print current dir
			Unfinish()
		elif cmd == "ls":
			Unfinish()
			# ls -l 
		elif cmd == "mkdir":
			Unfinish()
			# mkdir /temp/test
		elif cmd == "touch":
			Unfinish()
			# create a new file
		elif cmd == "rm":
			Unfinish()
			# rm [file]
			# rm -r [dir]
		elif cmd == "cp":
			Unfinish()
			# cp src dst(file/dir)
			# cp -r srcdir dstdir
		elif cmd == "chmod":
			# set perm
			Unfinish()
		elif cmd == "mv":
			Unfinish()
			# mv src to dst
		elif cmd == "read":
			# download the file abd print it on the screen
			Unfinish()
		elif cmd == "write":
			# download the file abd print it on the screen
			Unfinish()
		elif cmd == "upload":
		# upload your file
			Unfinish()
		elif cmd == "download":
			# download your file
			Unfinish()
		elif cmd == "share":
			Unfinish()
		else:
			print "Unknown operations for file system."
			print "Please check command! "
			usage()
			return
	except KeyError as ke:
		print "Couldn't get excepted args."
		print ke
	

class MyHandle(SocketServer.BaseRequestHandler):
	def receive(self):
		packet = None
		while 1:
			type = self.request.recv(1)
			if type is None or type == "" or type == " ":
				continue
			else:
				type = int(type)
				break;
		if type == 1:
			# packet: length + {}
			packet_length = 0
			# Get the length of packet
			data = ""
			while 1:
				# TCP receive data by Bytes
				data = self.request.recv(1)
				if data is None or data == "" or data ==" ":
					continue
				elif data == "{":
					break
				else:
					try:
						length_digit = int(data)
					except:
						return 0, 'error'
					packet_length = (packet_length * 10) + length_digit
					print packet_length
			
			# Get the full Packet
			data = "{"
			remaining_length = packet_length - len(data)
			while remaining_length > 0:
				buf = self.request.recv(min(remaining_length, MAXBUFF))
				if buf is None or buf == "":
					continue
				data += buf
				remaining_length = packet_length - len(data)
				print remaining_length
			
			# recover json
			argvs = json.loads(data)
			print argvs
			return type, argvs
		else:
			buf = self.request.recv(MAXBUFF)
			print "Test connection: ", buf
			return type, buf
			# self.request.sendall(buf.upper())
			
	def handle(self):
		type, buf = self.receive()
		if type == 1:
			argvs = buf
			response = json.dumps(handle_request(argvs))
		else:
			response = buf.upper()
		self.request.sendall(response)
	
if __name__ == '__main__':
	if CheckInitSet() > 0:
		# TODO:
		# 	Get users, files, acls
		# 	OR connect to the mysql
		print "Server is ready for connection"
	else:
		print "Waiting for  initialize..."
		_InitServer()
		print "Server is ready for connection"
	
	s_conn = SocketServer.ThreadingTCPServer((HOST, PORT), MyHandle)
	print 'Listening at', s_conn.server_address
	
	thread = threading.Thread(target=s_conn.serve_forever, name=servername)
	print 'This connection is in the Thread', thread.getName()
	thread.start()
	
	try:
		s_conn.serve_forever()
	except KeyboardInterrupt as ki:
		print "Close the server"
		s_conn.shutdown()
		exit()
		
