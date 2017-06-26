#!/usr/bin/env python2.7
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import base64

HOME_DIRECTORY = os.path.join(os.environ['HOME'], 'SFS_local')

class User:
	def __init__(self, Username):
		self.name = Username
		self.ROOT = os.path.join(HOME_DIRECTORY, Username)
		self.PRK = None
		self.PK = None
		self.ASEKEY = None
		self.cipher = None
	def setKey(self):
		prkfile = os.path.join(self.ROOT, Username + "_PRK.pem")
		pkfile = os.path.join(self.ROOT, Username + "_PK.pem")
		with open(prkfile) as f:
			self.PRK = RSA.importKey(f.read())
		with open(pkfile) as f:
			self.PK = RSA.importKey(f.read())
	def setAESKey(self):
		keyfile = os.path.join(self.ROOT, Username + "_AESKEY.pem")
		with open(keyfile) as f:
			self.ASEKEY = f.read()
		self.cipher = AES.new(base64.b64decode(key))
	def getPRK(self):
		return self.PRK
		
	def getPK(self):
		return self.PK
	
	def CreateRequest(self, data):
		msg = {}
		msg['username'] = self.name
		msg['signature'] = self.PRK.encrypt(json.dumps(data))
		msg['data'] = data
		return msg
	