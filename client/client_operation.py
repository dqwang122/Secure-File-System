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
    chmod [dst] [mode]		set perm for file or directory
    
    #File methods#
    read			read file from remote file server
    write [filename] [data]	write data to file of remote file server
	
    #Other methods#
    upload			upload file to remote server
    download			download file from remote server
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

def Unfinish():
	print "This function has not been completed..."