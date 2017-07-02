#!/usr/bin/env python2.7
import copy

READ = 1
WRITE = 2
EXEC = 3
UNABLE = 0

FILE = 1
DIR = 0

class Inode:
	def __init__(self, username, filename, type=FILE):
		self.username = username
		self.filename = filename
		self.perm = WRITE
		self.sharebit = 0
		self.share = {}
		self.sharekey = None
		self.type = type
	def chfilename(self, filename):
		self.filename = copy.deepcopy(filename)
	def setperm(self, perm):
		self.perm = perm
	def setshareperm(self, sharename, perm):
		self.share[sharename] = perm
	def checkperm(self, require):
		if self.perm >= require:
			return True
		else:
			return False
	def checkshareperm(self, username, require):
		if not username in self.share.keys():
			return False
		else:
			if self.share[username] > require:
				return True
			else:
				return False