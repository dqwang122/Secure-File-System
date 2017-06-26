import os
import sys

from error import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

HOUSE_ROOT = os.path.join(os.environ['HOME'], 'SFS_server')

def InitRemoteDir(username):
	USER_REMOTE_ROOT = os.path.join(HOUSE_ROOT, username)
	if not os.path.exists(USER_REMOTE_ROOT):
		os.makedirs(USER_REMOTE_ROOT)
	

def checkuser(users, username, password):
	repo = {}
	if username not in users.keys():
		repo["status"] = 'False'
		repo["data"] = USERNAME_ERR
	elif users[username]["password"] != password:
		repo["status"] = 'False'
		repo["data"] = PASSWORD_ERR
	else:
		repo["status"] = 'OK'
		repo["data"] = "Welcome!"
	return repo

def register(users, username, password, data, SERVER_PK):
	repo = {}
	users[username] = {}
	users[username]["password"] = password
	users[username]["USER_PK"] = RSA.construct((long(data['USER_PK']['N']),long(data['USER_PK']['e'])))
	repo["status"] = 'OK'
	repo["data"] = {}
	repo["data"]["SERVER_PK"] = {'N':SERVER_PK.n,'e':SERVER_PK.e}
	InitRemoteDir(username)
	return repo
		
def Unfinish():
	print "This function has not been complete..."