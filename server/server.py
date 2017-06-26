#!/usr/bin/python
# -*- coding:utf-8 -*-
import socket	#socket
import SocketServer
import os
import threading, getopt, sys, string
import json
import pickle

sys.path.append('../')

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5

from error import *
from server_operations import * 
from server_helper import *
import chunk_encrypt as c

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

# file system
ROOT = "./_init_"
HOUSE_DIRECTORY = os.path.join(os.environ['HOME'], 'SFS_server')

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
	global SERVER_PK,SERVER_PRK
	SERVER_PRK = RSA.generate(RSA_KEY_SIZE)
	SERVER_PK = SERVER_PRK.publickey()
	f = open(os.path.join(ROOT, "server_pk.pem"), 'w')
	f.write(SERVER_PK.exportKey('PEM'))
	f.close()
	f = open(os.path.join(ROOT, "server_prk.pem"), 'w')
	f.write(SERVER_PRK.exportKey('PEM'))
	f.close()

def CheckInitSet():
	global SERVER_PK,SERVER_PRK
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
	
	return True
		
def _GetUSERS():
	global users
	userfile = os.path.join(ROOT, "users.list")
	if os.path.exists(userfile):
		f = open(userfile)
		users = pickle.load(f)
		f.close()
	else:
		users = {}
	return True
	
def _UpdateUSERS():
	global users
	userfile = os.path.join(ROOT, "users.list")
	f = open(userfile, 'w')
	pickle.dump(users, f)
	f.close()
	return True

def _GETFILES(username):
	files_load = os.path.join(ROOT, username + "_files.list")
	if os.path.exists(files_load):
		f = open(files_load)
		files = pickle.load(f)
		f.close()
	else:
		files = []
	return files

	
def handle_request(argvs):
	try:
		data = argvs["data"]
		username = argvs["username"]
		cmd = data["cmd"]
		if cmd == "checkuser":
			password = data["password"]
			repo = checkuser(users, username, password)
			msg = json.dumps(repo)
			return msg
		elif cmd == "register":
			password = data["password"]
			if username in users.keys():
				repo = {}
				repo["status"] = 'False'
				repo["data"] = Duplicate_ERR
			else:
				repo = register(users, username, password, data, SERVER_PK)
				_UpdateUSERS()
			msg = json.dumps(repo)
			return msg
		elif cmd == "requirePK":
			repo = givePK(SERVER_PK)
			msg = json.dumps(repo)
			return msg
		elif cmd == "cd":
			user_pk =  users[username]["USER_PK"]
			return Unfinish(user_pk)
		elif cmd == "ls":
			user_pk =  users[username]["USER_PK"]
			return Unfinish(user_pk)
			# ls -l 
		elif cmd == "mkdir":
			user_pk =  users[username]["USER_PK"]
			return Unfinish(user_pk)
			# mkdir /temp/test
		elif cmd == "touch":
			user_pk =  users[username]["USER_PK"]
			return Unfinish(user_pk)
			# create a new file
		elif cmd == "rm":
			user_pk =  users[username]["USER_PK"]
			return Unfinish(user_pk)
			# rm [file]
			# rm -r [dir]
		elif cmd == "cp":
			user_pk =  users[username]["USER_PK"]
			return Unfinish(user_pk)
			# cp src dst(file/dir)
			# cp -r srcdir dstdir
		elif cmd == "chmod":
			# set perm
			user_pk =  users[username]["USER_PK"]
			return Unfinish(user_pk)
		elif cmd == "mv":
			user_pk =  users[username]["USER_PK"]
			return Unfinish(user_pk)
			# mv src to dst
		elif cmd == "read":
			# download the file abd print it on the screen
			user_pk =  users[username]["USER_PK"]
			return Unfinish(user_pk)
		elif cmd == "write":
			# download the file abd print it on the screen
			user_pk =  users[username]["USER_PK"]
			return Unfinish(user_pk)
		elif cmd == "upload":
		# upload your file
			user_pk =  users[username]["USER_PK"]
			return Unfinish(user_pk)
		elif cmd == "download":
			# download your file
			user_pk =  users[username]["USER_PK"]
			return Unfinish(user_pk)
		elif cmd == "share":
			user_pk =  users[username]["USER_PK"]
			return Unfinish(user_pk)
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
				break
		if type == 1 or type == 2:
			try:
				# packet: length + {}
				packet_length = 0
				
				# Get the length of packet
				while 1:
					# TCP receive data by Bytes
					data = self.request.recv(1)
					if data is None or data == "" or data ==" ":
						continue
					elif data == "|":
						break
					else:
						length_digit = int(data)
						packet_length = (packet_length * 10) + length_digit
				
				# Get the full Packet
				data = ""
				remaining_length = packet_length
				while remaining_length > 0:
					buf = self.request.recv(min(remaining_length, MAXBUFF))
					if buf is None or buf == "":
						continue
					data += buf
					remaining_length = packet_length - len(data)
				return type, data
			except:
				return 0, 'argvs analysis error'
		else:
			buf = self.request.recv(MAXBUFF)
			print "Test connection: ", buf
			return type, buf
			# self.request.sendall(buf.upper())
			
	def handle(self):
		type, data = self.receive()
		if type == 1:
			ciphertxts = json.loads(data)
			ciphertxt = ciphertxts["ciphertxt"]
			plaintxt = c.decrypt(SERVER_PRK, ciphertxt)
			print 'plaintxt', plaintxt
			argvs = json.loads(plaintxt)
			response = handle_request(argvs)
			print 'plaintxt', plaintxt
		elif type == 2:
			plaintxt = data
			argvs = json.loads(plaintxt)
			response = handle_request(argvs)
			print 'plaintxt', plaintxt
		else:
			response = data.upper()
		self.request.sendall(response)
	
if __name__ == '__main__':
	if CheckInitSet() > 0:
		_GetUSERS()
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
		
