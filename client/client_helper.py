#!/usr/bin/env python2.7
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.Hash import SHA
import base64
import json

import chunk_encrypt as c

BLOCK_SIZE = 32
HOME_DIRECTORY = os.path.join(os.environ['HOME'], 'SFS_local')
HOUSE_DIRECTORY = os.path.join(os.environ['HOME'], 'SFS_server')

class User:
	def __init__(self, Username):
		self.name = Username
		self.ROOT = os.path.join(HOME_DIRECTORY, Username)
		self.REMOTE_ROOT = os.path.join('SFS_server', Username)
		self.localpath = self.ROOT
		self.remotepath = self.REMOTE_ROOT

		prkfile = os.path.join(self.ROOT, self.name + "_PRK.pem")
		pkfile = os.path.join(self.ROOT, self.name + "_PK.pem")

		try:
			with open(prkfile) as f:
				self.PRK = RSA.importKey(f.read())
			with open(pkfile) as f:
				self.PK = RSA.importKey(f.read())

			keyfile = os.path.join(self.ROOT, self.name + "_AESKEY.pem")
			with open(keyfile) as f:
				self.ASEKEY = f.read()
			self.cipher = AES.new(base64.b64decode(self.ASEKEY))
		except:
			print "The User information is lost"

	def getcurDir(self):
		servername = self.remotepath.split("/")[0]
		return servername + ":" + "".join(self.remotepath.split("/")[1:])

	def chRemoteDir(self, path):
		self.remotepath = path
	
	def createRequest(self, data):
		msg = {}
		msg['username'] = self.name
		msg['signature'] = self.signatureData(json.dumps(data))
		msg['data'] = data
		return json.dumps(msg)

	def decryptRequest(self, ciphertxt):
		ciphertxts = json.loads(ciphertxt)
		ciphertxt = ciphertxts["ciphertxt"]
		plaintxt = c.decrypt(self.PRK, ciphertxt,False)
		return plaintxt

	def encryptAES(self, plaintxt):
		def _padString(s):
			return s + ((BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE))
		return base64.b64encode(self.cipher.encrypt(_padString(plaintxt)))

	def decryptAES(self, ciphertext):
		def _unPad(s):
			return s[:-ord(s[len(s) - 1:])]
		return _unPad(self.cipher.decrypt(base64.b64decode(ciphertext)).decode('utf-8'))

	def signatureData(self, data):
		signer = Signature_pkcs1_v1_5.new(self.PRK)
		digest = SHA.new()
		digest.update(data)
		sign = signer.sign(digest)
		return base64.b64encode(sign)