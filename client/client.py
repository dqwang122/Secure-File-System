import socket
import json
import base64
import os
import sys

sys.path.append('../')

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random

from error import *
from client_operation import *
from client_helper import *
from client_transmit import *
from encrypt import *

HOME_DIRECTORY = os.path.join(os.environ['HOME'], 'SFS_local')

# Crypto settings
RSA_KEY_SIZE = 2048
SERVER_PK = None

CURRENT_USER = None
CURRENT_DIRECTORY = None
CURRENT_DIRECTORY_SK = None
CURRENT_PATH = ""

HOST = '127.0.0.1'	#localhost
PORT = 8001

def _generateUserKey(Username, USER_ROOT):
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
	return USER_PRK, USER_PK
	
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
		USER_ROOT = os.path.join(HOME_DIRECTORY, Username)
		if not os.path.exists(USER_ROOT):
			os.makedirs(USER_ROOT)
		USER_PRK, USER_PK = _generateUserKey(Username, USER_ROOT)
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
	global CURRENT_USER, SERVER_PK
	CURRENT_USER = User(Username)
	skfile = os.path.join(CURRENT_USER.ROOT, "SERVER_PK.pem")
	try:
		with open(skfile) as f:
			SERVER_PK = RSA.importKey(f.read())
	except:
		RequireServerPK(Username, CURRENT_USER.ROOT, HOST, PORT)
	print "Hello! Welcome to Secure File System!"
	print "You can enter 'help' to find what file operations this system supports."
	return

def _GenerateCMD(data):
	plain_packet = CURRENT_USER.createRequest(data)
	cipher_repo = TransmitToServer(plain_packet, (HOST, PORT), SERVER_PK)
	plain_repo = CURRENT_USER.decryptRequest(cipher_repo)
	print "plain_repo", plain_repo
	repo = json.loads(plain_repo)
	return repo

def dispatch(cmd, argv):
	global CURRENT_USER, SERVER_PK
	if cmd == "quit" or cmd == "q":
		print "Bye"
		exit()
	elif cmd == "help" or cmd == "h":
		usage()
	elif cmd == "cd":
		# Unfinish()
		# print argv,len(argv)
		if len(argv) == 1:
			dstdir, curdir = DealWithAddr(CURRENT_USER, argv[0])
			data = {"cmd": cmd, "dstdir": dstdir, 'curdir':curdir}
			repo = _GenerateCMD(data)
			if repo["status"] == "OK":
				curpath = []
				curpath.append(repo["data"]["curpath"][0])
				for dir in repo["data"]["curpath"][1:]:
					curpath.append(CURRENT_USER.decryptAES(dir))
				curpathstr = '/'.join(curpath)
				print curpath
				CURRENT_USER.chRemoteDir(curpathstr)
				print CURRENT_USER.getcurDir()
			else:
				print repo["data"]
		else:
			print "illegal argvs for " + cmd
	elif cmd == "pwd":
		# print current dir
		print CURRENT_USER.getcurDir()
	elif cmd == "ls":
		curdir = CURRENT_USER.getEncryptcurDir()
		data = {"cmd": cmd, 'curdir': curdir}
		repo = _GenerateCMD(data)
		if repo["status"] == "OK":
			fileList = []
			for f in repo["data"]["fileList"]:
				fileList.append(CURRENT_USER.decryptAES(f))
			fileList = sorted(fileList)
			for f in fileList:
				print f + "\t",
			print '\n'
		else:
			print repo["data"]
		# Unfinish()
		# ls -l 
	elif cmd == "mkdir":
		if len(argv) == 1:
			dstdir, curdir = DealWithAddr(CURRENT_USER, argv[0])
			data = {"cmd": cmd, "dstdir": dstdir, 'curdir': curdir}
			repo = _GenerateCMD(data)
			if repo["status"] == "OK":
				print "Create a new directory at " + argv[0]
			else:
				print repo["data"]
		else:
			print "illegal argvs for " + cmd + ':' + str(len(argv))
		# Unfinish()
		# mkdir /temp/test
	elif cmd == "touch":
		if len(argv) == 1:
			filename, curdir = DealWithAddr(CURRENT_USER, argv[0])
			print filename
			data = {"cmd": cmd, "filename": filename, 'curdir':curdir}
			repo = _GenerateCMD(data)
			if repo["status"] == "OK":
				print "Create a new file at " + argv[0]
			else:
				print repo["data"]
		else:
			print "illegal argvs for " + cmd + ':' + str(len(argv))
		# Unfinish()
		# create a new file
	elif cmd == "rm":
		if len(argv) == 1:
			filename, curdir = DealWithAddr(CURRENT_USER, argv[0])
			print filename
			data = {"cmd": cmd, "filename": filename, 'curdir':curdir}
			repo = _GenerateCMD(data)
			if repo["status"] == "OK":
				print "Delete a file at " + argv[0]
			else:
				print repo["data"]
		elif len(argv) == 2 and argv[0] == '-r':
			dstdir, curdir = DealWithAddr(CURRENT_USER, argv[1])
			print dstdir
			data = {"cmd": cmd, "dstdir": dstdir, 'curdir': curdir}
			repo = _GenerateCMD(data)
			if repo["status"] == "OK":
				print "Delete a directory  at " + argv[1]
			else:
				print repo["data"]
		else:
			print "illegal argvs for " + cmd + ':' + str(len(argv))
		# Unfinish()
		# rm [file]
		# rm -r [dir]
	elif cmd == "cp":
		if len(argv) == 2:
			src, curdir = DealWithAddr(CURRENT_USER, argv[0])
			dst, curdir = DealWithAddr(CURRENT_USER, argv[1])
			data = {"cmd": cmd, "src": src, 'dst':dst, 'curdir':curdir}
			repo = _GenerateCMD(data)
			if repo["status"] == "OK":
				print "Copy", argv[0], 'to', argv[1]
			else:
				print repo["data"]
		elif len(argv) == 3 and argv[0] == '-r':
			srcdir, curdir = DealWithAddr(CURRENT_USER, argv[0])
			dstdir, curdir = DealWithAddr(CURRENT_USER, argv[1])
			data = {"cmd": cmd, "srcdir": srcdir, 'dstdir': dstdir, 'curdir': curdir}
			repo = _GenerateCMD(data)
			if repo["status"] == "OK":
				print "Copy Dir", argv[1], 'to', argv[2]
			else:
				print repo["data"]
		else:
			print "illegal argvs for " + cmd + ':' + str(len(argv))
		# Unfinish()
		# cp src dst(file/dir)
		# cp -r srcdir dstdir
	elif cmd == "chmod":
		# set perm
		if len(argv) == 2:
			obj, curdir = DealWithAddr(CURRENT_USER, argv[0])
			data = {"cmd": cmd, "obj": obj, 'perm':argv[1], 'curdir':curdir}
			repo = _GenerateCMD(data)
			if repo["status"] == "OK":
				oldperm = repo["data"]["oldperm"]
				if oldperm == 1:
					oldermstr = "READ"
				elif oldperm == 2:
					oldermstr = "WRITE"
				elif oldperm == 3:
					oldermstr = "EXEC"
				elif oldperm == 0:
					oldermstr = "UNABLE"
				newperm = repo["data"]["newperm"]
				if newperm == 1:
					newperm = "READ"
				elif newperm == 2:
					newperm = "WRITE"
				elif newperm == 3:
					newperm = "EXEC"
				elif newperm == 0:
					newperm = "UNABLE"
				print "Set ", argv[0], 'from', oldermstr, 'to', newperm
			else:
				print repo["data"]
		else:
			print "illegal argvs for " + cmd + ':' + str(len(argv))
		# Unfinish()
	elif cmd == "mv":
		if len(argv) == 2:
			src, curdir = DealWithAddr(CURRENT_USER, argv[0])
			dst, curdir = DealWithAddr(CURRENT_USER, argv[1])
			data = {"cmd": cmd, "src": src, 'dst':dst, 'curdir':curdir}
			repo = _GenerateCMD(data)
			if repo["status"] == "OK":
				print "Move ", argv[0], ' to ', argv[1]
			else:
				print repo["data"]
		else:
			print "illegal argvs for " + cmd + ':' + str(len(argv))
		# Unfinish()
		# mv src to dst
	elif cmd == "read":
		# download the file abd print it on the screen
		if len(argv) == 1:
			fileremotepath = argv[0]
			dst = os.path.join(CURRENT_USER.ROOT, 'temp')
			if not os.path.exists(dst):
				os.makedirs(dst)
			src, curdir = DealWithAddr(CURRENT_USER, fileremotepath)
			data = {"cmd": 'download', "src": src, 'curdir':curdir}
			repo = _GenerateCMD(data)
			if repo["status"] == "OK":
				content = repo["data"]["content"]
				filename = repo["data"]["filename"]
				full_path = Decryptfile(CURRENT_USER, dst, content, filename)
				print "Download ", argv[0], ' to ', dst
				ShowonScreen(full_path)
			else:
				print repo["data"]
		else:
			print "illegal argvs for " + cmd + ':' + str(len(argv))
		# Unfinish()
	elif cmd == "write":
		# download the file abd print it on the screen
		if len(argv) == 2:
			fileremotepath = argv[0]
			temp_content = argv[1].decode('utf-8')
			dst = os.path.join(CURRENT_USER.ROOT, 'temp')
			if not os.path.exists(dst):
				os.makedirs(dst)
			src, curdir = DealWithAddr(CURRENT_USER, fileremotepath)
			data = {"cmd": 'download', "src": src, 'curdir':curdir}
			repo = _GenerateCMD(data)
			if repo["status"] == "OK":
				content = repo["data"]["content"]
				filename = repo["data"]["filename"]
				full_path = Decryptfile(CURRENT_USER, dst, content, filename)
				print "Download ", argv[0], ' to ', dst

				ShowonScreen(full_path)
				print "After update:"
				WriteFile(full_path, temp_content)

				print isinstance(filename, unicode)
				filename, content = GetEnLocalfFile(CURRENT_USER, full_path)
				full_path, curdir = DealWithAddr(CURRENT_USER, argv[1])
				print 'src',src
				data = {"cmd": 'upload', "filename": filename, 'content': content, 'dst': src[:-1], 'curdir': curdir}
				repo = _GenerateCMD(data)
				if repo["status"] == "OK":
					print "Upload ", argv[0], ' to ', argv[1]
				else:
					print repo["data"]

			else:
				print repo["data"]
		else:
			print "illegal argvs for " + cmd + ':' + str(len(argv))
		# Unfinish()
	elif cmd == "upload":
		# upload your file
		if len(argv) == 2:
			filelocalpath = argv[0]
			filename, content = GetEnLocalfFile(CURRENT_USER, filelocalpath)
			dst, curdir = DealWithAddr(CURRENT_USER, argv[1])
			data = {"cmd": cmd, "filename": filename, 'content':content, 'dst':dst, 'curdir':curdir}
			repo = _GenerateCMD(data)
			if repo["status"] == "OK":
				print "Upload ", argv[0], ' to ', argv[1]
			else:
				print repo["data"]
		else:
			print "illegal argvs for " + cmd + ':' + str(len(argv))
		# Unfinish()
	elif cmd == "download":
		# download your file
		if len(argv) == 2:
			fileremotepath = argv[0]
			dst = argv[1]
			src, curdir = DealWithAddr(CURRENT_USER, fileremotepath)
			data = {"cmd": cmd, "src": src, 'curdir':curdir}
			repo = _GenerateCMD(data)
			if repo["status"] == "OK":
				content = repo["data"]["content"]
				filename = repo["data"]["filename"]
				Decryptfile(CURRENT_USER, dst, content, filename)
				print "Download ", argv[0], ' to ', argv[1]
			else:
				print repo["data"]
		else:
			print "illegal argvs for " + cmd + ':' + str(len(argv))
		# Unfinish()
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
					break
				if user_input.upper() == "Q":
					print "Bye"
					break
				else:
					cmd = user_input.split()[0]
					try:
						argv = user_input.split()[1:]
					except:
						argv = None
					dispatch(cmd, argv)
			except (ValueError, KeyboardInterrupt) as e:
				print e
				continue
	except EOFError as e:
		print "Bye~"
	except Exception as e:
		raise
		
		
	
