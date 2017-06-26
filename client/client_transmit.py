#!/usr/bin/env python
# -*- coding:utf-8 -*-
import socket
import os
import threading, sys, string

MAXBUFF = 2048

def CheckFromServer(plaintxt, (HOST, PORT)):
	try:
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		s.connect((HOST,PORT))
		type = 2	#plainmode
		length = len(plaintxt)
		msg = str(type) + ' ' + str(length) + '|' + plaintxt
		s.sendall(msg)
		repo = s.recv(MAXBUFF)
		return repo
	finally:
		s.close()