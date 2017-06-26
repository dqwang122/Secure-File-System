import socket
import json
import base64
import os
import sys

sys.path.insert(0, '../')

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

from error import *
from client_operation import *
from client_helper import *
from client_transmit import *
from encrypt import *

HOME_DIRECTORY = os.path.join(os.environ['HOME'], 'SFS_local')

# Crypto settings
RSA_KEY_SIZE = 2048
SERVER_PK = None

USER_ROOT = None
USER_PRK = None
USER_PK = None

CURRENT_USER = None
CURRENT_DIRECTORY = None
CURRENT_DIRECTORY_SK = None
CURRENT_PATH = ""

HOST = '127.0.0.1'	#localhost
PORT = 8001

def _generateUserKey(Username):
	global USER_PRK, USER_PK
	USER_PRK = RSA.generate(RSA_KEY_SIZE)
	USER_PK = USER_PRK.publickey()
	f = open(os.path.join(USER_ROOT, Username + "_PK.pem"), 'w')
	f.write(USER_PK.exportKey('PEM'))
	f.close()
	f = open(os.path.join(USER_ROOT, Username + "_PRK.pem"), 'w')
	f.write(USER_PRK.exportKey('PEM'))
	f.close()
	keyfile = os.path.join(USER_ROOT, Username + "_AESKEY.pem")
	USER_ASEKEY = base64.b64encode(Random.new().read(32))
	with open(keyfile, 'w') as f:
		f.write(USER_ASEKEY)
	
# Connect to server to check user
def AccountCheck(Username, Password):
	# return USERNAME_ERR
	# return PASSWORD_ERR
	keydir = os.path.join(HOME_DIRECTORY, Username)
	prkfile = os.path.join(keydir, Username + "_PRK.pem")
	pkfile = os.path.join(keydir, Username + "_PK.pem")
	if not os.path.exists(prkfile) or not os.path.exists(pkfile):
		return USERNAME_ERR
	else:
		msg = {}
		msg['username'] = Username
		msg['data'] = {'cmd':'checkuser', 'password':Password}
		plaintxt = json.dumps(msg)
		repo = CheckFromServer(plaintxt, (HOST, PORT))
		repo = json.loads(repo)
		if repo['status'] != 'OK':
			return repo['data']
	return True

def Register(Username, Password):
	# return Duplicate_ERR
	global SERVER_PK
	msg = {}
	msg['username'] = Username
	msg['data'] = {'cmd':'checkuser', 'password':Password}
	plaintxt = json.dumps(msg)
	repo = CheckFromServer(plaintxt, (HOST, PORT))
	repo = json.loads(repo)
	if repo['status'] == 'False' and repo['data'] == USERNAME_ERR:
		global USER_ROOT
		USER_ROOT = os.path.join(HOME_DIRECTORY, Username)
		if not os.path.exists(USER_ROOT):
			os.makedirs(USER_ROOT)
		_generateUserKey(Username)
		msg = {}
		msg['username'] = Username
		msg['data'] = {'cmd':'register', 'password':Password, 'USER_PK':{'N':USER_PK.n,'e':USER_PK.e}}
		plaintxt = json.dumps(msg)
		repo = CheckFromServer(plaintxt, (HOST, PORT))
		repo = json.loads(repo)
		if repo['status'] == 'OK':
			SERVER_PK = RSA.construct((long(repo['data']['SERVER_PK']['N']),
                                   long(repo['data']['SERVER_PK']['e'])))
			skfile = os.path.join(USER_ROOT, "SERVER_PK.pem")
			with open(skfile, 'w') as f:
				f.write(SERVER_PK.exportKey('PEM'))
			print "Register successfully!"
		else:
			return repo["data"]
	else:
		return Duplicate_ERR
	return True

def Login():
	global Current_User
	Current_User = User(Username) 
	print "Hello! Welcome to Secure File System!"
	print "You can enter 'help' to find what file operations this system supports."
	return
	
def dispatch(cmd, argv):
	if cmd == "cd":
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


if __name__ == '__main__':
	Username = raw_input("Username: ")
	Password = raw_input("Password: ")
	check = AccountCheck(Username, Password)
	if check == True:
		Login()
	elif check == USERNAME_ERR:
		print "It seems that you HAVE NOT had an account. Do you want to create one?"
		choose = raw_input("Y or N: ")
		if choose.upper() == 'Y':
			Username = raw_input("Username: ")
			Password = raw_input("Password: ")
			while Register(Username, Password) < 0:
				print "This Username have been used, please choose another one."
				Username = raw_input("Username: ")
				Password = raw_input("Password: ")
			Login()
		elif choose.upper() == "N":
			print "Bye~"
			exit()
	elif check == PASSWORD_ERR:
		print "It seems that you have WRONG password. Try again!"
		Password = raw_input("Password: ")
		check = AccountCheck(Username, Password)
		if check == True:
			Login()
		else:
			print "Wrong again...Bye~"
			exit()
	else:
		print "Bye~"
		exit()
	
	# Enter the system
	try:
		while 1:
			try:
				user_input = raw_input(Username + ' > ')
				if not user_input:
					break;
				if user_input.upper() == "Q":
					print "Bye"
					break
				else:
					cmd = user_input.split()[0]
					
					if cmd == "quit" or cmd == "q":
						print "Bye"
						break
					elif cmd == "help" or cmd == "h":
						usage()
					elif len(user_input.split()) == 1:
						print "Unsupported operation for file system."
						print "Please check command: "
						usage()
					else:
						argv = user_input.split()[1:]
						dispatch(cmd, argv)
			except (ValueError, KeyboardInterrupt) as e:
				print e
				continue
	except EOFError as e:
		print "Bye~"
	except Exception as e:
		raise
		
		
	
