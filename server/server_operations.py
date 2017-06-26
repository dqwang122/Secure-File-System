import os
import sys

from error import *
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.Hash import SHA
from Crypto.Cipher import AES
import base64
import json

import chunk_encrypt as c

HOUSE_DIRECTORY = os.path.join(os.environ['HOME'], 'SFS_server')

def usage():
	print """
    -h --help             print the help
    -l --list             Maximum number of connections
    -p --port             To monitor the port number 
	"""

def InitRemoteDir(username):
	USER_REMOTE_ROOT = os.path.join(HOUSE_DIRECTORY, username)
	if not os.path.exists(USER_REMOTE_ROOT):
		os.makedirs(USER_REMOTE_ROOT)

def CheckSignature(USER_PK, signature, data):
	verifier = Signature_pkcs1_v1_5.new(USER_PK)
	digest = SHA.new()
	digest.update(data)
	return verifier.verify(digest, base64.b64decode(signature))


def CreateStandardPacket(user_pk, msg):
	print user_pk
	ciphertxt = c.encrypt(user_pk, msg, False)
	ciphertxts = json.dumps({"ciphertxt": ciphertxt})
	length = len(ciphertxts)
	packet = str(length) + '|' + ciphertxts
	return packet

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

def givePK(SERVER_PK):
	repo = {}
	repo["status"] = 'OK'
	repo["data"] = {}
	repo["data"]["SERVER_PK"] = {'N': SERVER_PK.n, 'e': SERVER_PK.e}
	return repo
		
def Unfinish(user_pk):
	repo = {}
	repo["status"] = "False"
	repo["data"] = "This function has not been complete..."
	msg = json.dumps(repo)
	standard_packet = CreateStandardPacket(user_pk, msg)
	return standard_packet