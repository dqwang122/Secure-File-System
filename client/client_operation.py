import os
import sys
import json
from client_transmit import *
from Crypto.PublicKey import RSA


def usage():
	print """
    help			print the help
    quit			quit the file system
	
    #Filesystem methods#
    cd				change the directory
    pwd				print current directory
    ls				list file under the directory
    mkdir			create a new directory
    touch			create a new file
    rm				remove a file or directory(-r)
    cp [src] [dst]		copy src to dst (directory with -r)
    mv [src] [dst]		move or rename src to dst (file or directory)
    chmod [dst] [mode]		set perm for file or directory(mode=R,W,E,U)
    
    #File methods#
    read [remotefile]			read file from remote file server
    write [remotefile] [data]	write data to file of remote file server
	
    #Other methods#
    upload [localfile] [dst]			upload file to remote server
    download [remotefile] [dst]		download file from remote server
    share -f -u [mode]		share with others

	"""

def RequireServerPK(Username, USER_ROOT, HOST, PORT):
	msg = {}
	msg['username'] = Username
	msg['data'] = {'cmd': 'requirePK'}
	plaintxt = json.dumps(msg)
	repo = CheckFromServer(plaintxt, (HOST, PORT))
	repo = json.loads(repo)
	if repo['status'] == 'OK':
		SERVER_PK = RSA.construct((long(repo['data']['SERVER_PK']['N']),
								   long(repo['data']['SERVER_PK']['e'])))
		skfile = os.path.join(USER_ROOT, "SERVER_PK.pem")
		with open(skfile, 'w') as f:
			f.write(SERVER_PK.exportKey('PEM'))
		print "Require successfully!"
	else:
		return repo["data"]

def DealWithAddr(CURRENT_USER, argv):
	dirs = argv.split('/')
	filename = []
	for d in dirs:
		if d == "." or d == ".." or d == "" or d == "~":
			filename.append(d)
		else:
			filename.append(CURRENT_USER.encryptAES(d))
	curpath = CURRENT_USER.getEncryptcurDir()
	print 'curDirs:', curpath
	return filename,curpath

def GetEnLocalfFile(CURRENT_USER, filelocalpath):
	f = open(filelocalpath)
	content = f.read()
	f.close()
	# print 'content', content

	en_content = CURRENT_USER.encryptAES(content)
	# print 'en_content', en_content

	filename = filelocalpath.split('/')[-1]
	en_filename = CURRENT_USER.encryptAES(filename)
	return en_filename, en_content

def Decryptfile(CURRENT_USER, dst, content, filename):
	def _unPad(s):
		return s[:-ord(s[len(s) - 1:])]

	de_filename = _unPad(CURRENT_USER.cipher.decrypt(base64.b64decode(filename)))
	# print 'de_filename', de_filename
	# print "content", content
	if content:
		de_content = CURRENT_USER.decryptAES(content)
	else:
		de_content = content
	# print 'de_content', de_content
	full_path = os.path.join(dst,de_filename)
	f = open(full_path, 'wb')
	f.write(de_content)
	f.close()
	return full_path

def ShowonScreen(dst):
	f = open(dst, 'r')
	print "This file is:"
	print f.read()
	f.close()

def WriteFile(dst, temp_content):
	f = open(dst, 'a')
	f.write(temp_content)
	f.close()

def Unfinish():
	print "This function has not been completed..."