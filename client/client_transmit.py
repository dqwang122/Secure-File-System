#!/usr/bin/env python
# -*- coding:utf-8 -*-
import socket
import os
import threading, sys, string
import base64
import json

from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto import Random

import chunk_encrypt as c

MAXBUFF = 2048

def CheckFromServer(plaintxt, (HOST, PORT)):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.connect((HOST,PORT))
		type = 2	#plainmode
		length = len(plaintxt)
		msg = str(type) + ' ' + str(length) + '|' + plaintxt
		s.sendall(msg)
		repo = s.recv(MAXBUFF)
		return repo
	finally:
		s.close()

def TransmitToServer(plaintxt, (HOST, PORT),SERVER_PK):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.connect((HOST,PORT))
		type = 1	# cipher mode
		# print 'plaintxt', plaintxt
		# print SERVER_PK
		ciphertxt = c.encrypt(SERVER_PK, plaintxt)
		ciphertxts = json.dumps({"ciphertxt":ciphertxt})
		length = len(ciphertxts)
		msg = str(type) + ' ' + str(length) + '|' + ciphertxts
		s.sendall(msg)
		repo = ReceiveFromServer(s)
		return repo
	finally:
		s.close()

def ReceiveFromServer(s):
	try:
		# packet: length + {}
		packet_length = 0

		# Get the length of packet
		while 1:
			# TCP receive data by Bytes
			data = s.recv(1)
			if data is None or data == "" or data == " ":
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
			buf = s.recv(min(remaining_length, MAXBUFF))
			if buf is None or buf == "":
				continue
			data += buf
			remaining_length = packet_length - len(data)
		ciphertxt = data
		return ciphertxt
	except:
		return 0, 'argvs analysis error'