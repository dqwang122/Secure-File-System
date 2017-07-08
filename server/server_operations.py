import os
import sys

from error import *
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.Hash import SHA
from Crypto.Cipher import AES
import base64
import json
import shutil
import copy

import chunk_encrypt as c
from server_helper import *
from server_transmit import *

FILETYPR = -1

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

def InsertIntoFile(files, filepath):
	curdir = files
	for dir in filepath[:-1]:
		if dir not in curdir.keys():
			return WRONG_PATH
		curdir = curdir[dir]
	curdir[filepath[-1]] = FILETYPR
	return True

def CopyIntoFile(files, srcfilename, dstpath):
	print 'srcfilename:', srcfilename
	print 'dstpath:', dstpath
	curdir = files
	for dir in dstpath[:-1]:
		if dir not in curdir.keys():
			return WRONG_PATH
		curdir = curdir[dir]
	# if dst as dir
	if dstpath[-1] in curdir.keys() and curdir[dstpath[-1]] != FILETYPR :
		curdir = curdir[dstpath[-1]]
		curdir[srcfilename] = FILETYPR
	else:
		curdir[dstpath[-1]] = FILETYPR
	return True

def DirToDir(files, srcpath, dstpath):
	print 'srcpath',srcpath
	print 'dstpath', dstpath
	curdir = files
	for dir in dstpath[:-1]:
		if dir not in curdir.keys():
			return WRONG_PATH
		curdir = curdir[dir]
	if dstpath[-1] not in curdir.keys():
		curdir[dstpath[-1]] = {}
	else:
		return WRONG_PATH
	dstdir = curdir[dstpath[-1]]

	srccurdir = files
	for dir in srcpath:
		if dir not in srccurdir.keys():
			return WRONG_PATH
		srccurdir = srccurdir[dir]
	for file in srccurdir.keys():
		dstdir[file] = FILETYPR
	return True


def DeleteFromFile(files, path):
	curdir = files
	for dir in path[:-1]:
		if dir not in curdir.keys():
			return WRONG_PATH
		curdir = curdir[dir]
	if curdir[path[-1]] == FILETYPR:
		curdir.pop(path[-1])
	else:
		return DELETEDIR_ERROR
	return True

def DeleteFromDir(files, path):
	curdir = files
	for dir in path[:-1]:
		if dir not in curdir.keys():
			return WRONG_PATH
		curdir = curdir[dir]
	print curdir.pop(path[-1])
	return True

def CreateDirInto(files, filepath):
	curdir = files
	print 'filepath:', filepath
	for dir in filepath[:-1]:
		print 'dir', dir
		print 'curdir:', curdir
		if dir not in curdir.keys():
			return WRONG_PATH
		curdir = curdir[dir]
	curdir[filepath[-1]] = {}
	return True	

def Rename(files, srcpath, dstpath):
	curdir = files
	for dir in srcpath[:-1]:
		if dir not in curdir.keys():
			return WRONG_PATH
		curdir = curdir[dir]
	temp = curdir.pop(srcpath[-1])
	curdir[dstpath[-1]] = temp
	return True

def MoveFile2Dir(files, srcpath, dstpath):
	curdir = files
	for dir in dstpath:
		if dir not in curdir.keys():
			return WRONG_PATH
		curdir = curdir[dir]
	curdir[srcpath[-1]] = FILETYPR
	
	srccurdir = files
	for dir in srcpath[:-1]:
		if dir not in srccurdir.keys():
			return WRONG_PATH
		srccurdir = srccurdir[dir]
	srccurdir.pop(srcpath[-1])
	
	return True

def MoveDir2Dir(files, srcpath, dstpath):
	print 'srcpath',srcpath
	print 'dstpath', dstpath
	dstdir = files
	for dir in dstpath:
		if dir not in dstdir.keys():
			return WRONG_PATH
		dstdir = dstdir[dir]
	dstdir[srcpath[-1]] = {}
	dstdir = dstdir[srcpath[-1]]

	srccurdir = files
	for dir in srcpath:
		if dir not in srccurdir.keys():
			return WRONG_PATH
		srccurdir = srccurdir[dir]
	for file in srccurdir.keys():
		dstdir[file] = FILETYPR
		srccurdir.pop(file)
	return True
	
def TravserDir(files, inodes, curpath, dstpath, PERM=READ):
	curdir = files
	# curpath and dstpath are []
	travserpaths = []

	if not curpath or not dstpath:
		return PERMISSION_DENIED

	if dstpath[0] == '.':	# start with current path
		travserpaths.extend(curpath)
		travserpaths.extend(dstpath[1:])
	elif dstpath[0] == "..":
		cnt = 1
		while cnt < len(dstpath) and dstpath[cnt] == "..":
			cnt += 1
		if cnt >= len(curpath):
			return curdir, travserpaths, PERMISSION_DENIED
		else:
			travserpaths.extend(curpath[:-cnt])
			travserpaths.extend(dstpath[cnt:])
	elif dstpath[0] == "~":
		travserpaths.extend(curpath[0])
		travserpaths.extend(dstpath[1:])
	else:
		travserpaths.extend(curpath)
		travserpaths.extend(dstpath)

	print "currentpaths: ", curpath
	print "dstpaths: ", dstpath
	print "travserpaths: ", travserpaths

	cnt = 0
	for dir in travserpaths: # each level
		if dir not in curdir.keys():
			return curdir, travserpaths, WRONG_PATH
		else:
			curpathstr = '/'.join(travserpaths[:cnt+1])
			print 'curpathstr', curpathstr
			if curpathstr not in inodes.keys(): # every level must be in the inodes
				return curdir, travserpaths, WRONG_PATH
			if not inodes[curpathstr].checkperm(PERM):
				return curdir, travserpaths, PERMISSION_DENIED
			curdir = curdir[dir]

	return curdir, travserpaths, True

def changeDir(files, inodes, user_pk, dstdir, curdir):
	curdir, path, status = TravserDir(files, inodes, curdir, dstdir)
	if status == PERMISSION_DENIED:
		return  PermsDenied(user_pk)
	elif status == WRONG_PATH:
		return WrongPath(user_pk)

	if curdir == -1:
		return WrongPath(user_pk)

	repo = {}
	repo["status"] = "OK"
	repo["data"] = {"curpath": path}
	msg = json.dumps(repo)
	standard_packet = CreateStandardPacket(user_pk, msg)
	return standard_packet

def ListDir(files, inodes, user_pk, curdir):
	curlist, path, status = TravserDir(files, inodes, curdir, ['.'])
	curpathstr = '/'.join(curdir)
	print 'curlist: ', curlist
	print 'curlistvalue: ', curlist.values()

	fileList = []

	if curlist.keys():
		curlistf = curlist.keys()
		print 'curlistf:',curlistf
		for file in curlistf:
			total_path = os.path.join(curpathstr,file)
			print 'total_path:',total_path
			if total_path not in inodes.keys():
				continue
			if inodes[total_path].checkperm(READ):
				fileList.append(inodes[total_path].filename)

	repo = {}
	repo["status"] = "OK"
	repo["data"] = {"fileList": fileList}
	msg = json.dumps(repo)
	standard_packet = CreateStandardPacket(user_pk, msg)
	return standard_packet

def createnewfile(files, inodes, filename, username, user_pk, curdir):
	if len(filename) == 1:
		if filename[0] == "." or filename[0] == '..':
			return NothingHappen(user_pk)
		else:
			path = curdir
	else:
		_, path, status = TravserDir(files, inodes, curdir, filename[:-1], WRITE)
		if status == PERMISSION_DENIED:
			return  PermsDenied(user_pk)
		elif status == WRONG_PATH:
			return WrongPath(user_pk)

	pathstr = "/".join(path)
	print 'path', pathstr
	filepath = os.path.join(pathstr, filename[-1])
	abspath = os.path.join(HOUSE_DIRECTORY, filepath)
	print 'abspath', abspath

	# inode
	NewInode = Inode(username, filename[-1])
	if filepath not in inodes.keys():
		inodes[filepath] = NewInode
	print inodes

	# files
	path.append(filename[-1])
	if InsertIntoFile(files, path) == WRONG_PATH:
		return WrongPath(user_pk)
		
	fakedir = '/'.join(abspath.split('/')[:-1])
	print 'fakedir', fakedir
	if not os.path.exists(fakedir):
		os.makedirs(fakedir)
	try:
		os.mknod(abspath)
	except:
		return Duplicated(user_pk)

	return Completed(user_pk)

def deletefile(files, inodes, filename, username, user_pk, curdir):
	if len(filename) == 1:
		if filename[0] == "." or filename[0] == '..':
			return NothingHappen(user_pk)
		else:
			path = curdir
	else:
		_, path, status = TravserDir(files, inodes, curdir, filename[:-1], WRITE)
		if status == PERMISSION_DENIED:
			return PermsDenied(user_pk)
		elif status == WRONG_PATH:
			return WrongPath(user_pk)

	pathstr = "/".join(path)
	print 'path', pathstr
	filepath = os.path.join(pathstr, filename[-1])
	abspath = os.path.join(HOUSE_DIRECTORY, filepath)
	print 'abspath', abspath

	# files
	path.append(filename[-1])
	check = DeleteFromFile(files, path)
	if check == WRONG_PATH:
		return WrongPath(user_pk)
	elif check == DELETEDIR_ERROR:
		return DELETEDENIED(user_pk)
	
	# inode
	if filepath not in inodes.keys():
		return WrongPath(user_pk)
	elif not inodes[filepath].checkperm(WRITE):
		return PermsDenied(user_pk)
	else:
		inodes.pop(filepath)
	print inodes

	# untrust file server
	fakedir = '/'.join(abspath.split('/')[:-1])
	print fakedir
	if not os.path.exists(fakedir):
		return WrongPath(user_pk)
	try:
		os.remove(abspath)
	except:
		return OSError(user_pk)

	return Completed(user_pk)


def createnewdir(files, inodes, dstdir, username, user_pk, curdir):
	if len(dstdir) == 1:
		if dstdir[0] == "." or dstdir[0] == '..':
			return NothingHappen(user_pk)
		else:
			path = curdir
	else:
		_, path, status = TravserDir(files, inodes, curdir, dstdir[:-1],WRITE)
		if status == PERMISSION_DENIED:
			return  PermsDenied(user_pk)
		elif status == WRONG_PATH:
			return WrongPath(user_pk)

	pathstr = "/".join(path)
	print 'path', pathstr
	filepath = os.path.join(pathstr, dstdir[-1])
	abspath = os.path.join(HOUSE_DIRECTORY, filepath)
	print 'abspath', abspath

	# inode
	NewInode = Inode(username, dstdir[-1], DIR)
	if filepath not in inodes.keys():
		inodes[filepath] = NewInode
	else:
		return Duplicated(user_pk)
	print inodes
	
	# files
	path.append(dstdir[-1])
	if CreateDirInto(files, path) == WRONG_PATH:
		return WrongPath(user_pk)
		
	# untrust file server
	fakedir = copy.copy(abspath)
	print 'fakedir', fakedir
	if not os.path.exists(fakedir):
		os.makedirs(abspath)
		
	return Completed(user_pk)

def deletedir(files, inodes, dstdir, username, user_pk, curdir):
	if len(dstdir) == 1:
		if dstdir[0] == "." or dstdir[0] == '..':
			return NothingHappen(user_pk)
		else:
			path = curdir
	else:
		_, path, status = TravserDir(files, inodes, curdir, dstdir[:-1], WRITE)
		if status == PERMISSION_DENIED:
			return PermsDenied(user_pk)
		elif status == WRONG_PATH:
			return WrongPath(user_pk)

	pathstr = "/".join(path)
	print 'path', pathstr
	filepath = os.path.join(pathstr, dstdir[-1])
	abspath = os.path.join(HOUSE_DIRECTORY, filepath)
	print 'abspath', abspath

	# inode 
	if filepath not in inodes.keys():
		return WrongPath(user_pk)
	else:
		inodes.pop(filepath)

	for file in inodes.keys():
		if file.startswith(filepath):
			inodes.pop(file)
	print inodes

	# files
	path.append(dstdir[-1])
	check = DeleteFromDir(files, path)
	if check == WRONG_PATH:
		return WrongPath(user_pk)

	# untrust file server
	fakedir = abspath
	print 'fakedir', fakedir
	try:
		shutil.rmtree(abspath)
	except:
		return OSError(user_pk)

	return Completed(user_pk)

def copyfile(files, inodes, dst, src, username, user_pk, curdir):
	if len(src) == 1:
		if src[0] == "." or src[0] == '..':
			return NothingHappen(user_pk)
		else:
			srcpath = curdir
	else:
		_, srcpath, status = TravserDir(files, inodes, curdir, src[:-1])
		if status == PERMISSION_DENIED:
			return PermsDenied(user_pk)
		elif status == WRONG_PATH:
			return WrongPath(user_pk)
	print 'srcpath: ', srcpath

	if len(dst) == 1:
		if dst[0] == "." :
			dstpath = curdir
		elif dst[0] == '..':
			dstpath = curdir[:-1]
		else:
			dstpath = curdir
	else:
		_, dstpath, status = TravserDir(files, inodes, curdir, dst[:-1], WRITE)
		if status == PERMISSION_DENIED:
			return PermsDenied(user_pk)
		elif status == WRONG_PATH:
			return WrongPath(user_pk)
	print 'dstpath: ', dstpath

	srcpathstr = "/".join(srcpath)
	print 'srcpath: ', srcpathstr
	srcfilepath = os.path.join(srcpathstr, src[-1])
	srcabspath = os.path.join(HOUSE_DIRECTORY, srcfilepath)
	print 'srcabspath', srcabspath
	srcpath_copy = copy.copy(srcpath)

	dstpathstr = "/".join(dstpath)
	print 'dstdstpath: ', dstpathstr
	if dst[-1] != '..' and dst[-1] != '.':
		dstfilepath = os.path.join(dstpathstr, dst[-1])
		dstpath.append(dst[-1])
	else:
		dstfilepath = os.path.join(dstpathstr, '')

	# NewInode = Inode(username, filename[-1])
	# if filepath not in inodes.keys():
		# inodes[filepath] = NewInode
	# print inodes
	
	# inode
	if srcfilepath not in inodes.keys():
		return WrongPath(user_pk)
	elif inodes[srcfilepath].type == DIR:
		return COPYDENIED(user_pk)
	
	NewInode = copy.deepcopy(inodes[srcfilepath])
	
	if dstfilepath in inodes.keys() and inodes[dstfilepath].type == DIR:
		# the dst is a dir
		print 'dst Is a dir'
		dstfilepath = os.path.join(dstfilepath, src[-1])
		print 'totalpath:', dstfilepath
		inodes[dstfilepath] = NewInode
	elif dstfilepath in inodes.keys() and inodes[dstfilepath].type == FILE:
		print 'dst Is a file'
		NewInode.chfilename(dst[-1])
		inodes[dstfilepath] = NewInode
	else:
		return WrongPath(user_pk)

		# curdir = files
		# for dir in dstpath[:-1]:
			# if dir not in curdir.keys():
				# return WRONG_PATH
			# curdir = curdir[dir]
		# for dst as dir
		# if dstpath[-1] in curdir.keys() and curdir[dstpath[-1]] != FILETYPR:
			# dstfile = os.path.join(dstfilepath, src[-1])
			# inodes[dstfile] = NewInode
		# else:
			# inodes[dstfilepath] = NewInode

	print inodes

	# files
	if CopyIntoFile(files, src[-1], dstpath) == WRONG_PATH:
		return WrongPath(user_pk)

	# untrust file server
	if not os.path.exists(srcabspath):
		return WrongPath(user_pk)
		
	temp = src[-1].split('/')[0]
	fakesrc = '/'.join(srcpath_copy)
	fakesrc = '/'.join([fakesrc, temp])
	fakeabspath = os.path.join(HOUSE_DIRECTORY, fakesrc)
	print 'fakesrc:', fakesrc
	print 'fakeabspath:', fakeabspath
	
	if os.path.isdir(fakeabspath):
		print "copytree"
		
		dstabspath = os.path.join(HOUSE_DIRECTORY, dstfilepath)
		print 'dstabspath', dstabspath
		fakedir = '/'.join(dstabspath.split('/')[:-2])
		print 'fakedir:', fakedir
		if not os.path.exists(fakedir):
			os.makedirs(fakedir)
		
		dstdir = '/'.join(dstabspath.split('/')[:-1])
		shutil.copytree(fakeabspath, dstdir)
	else:
		print "copy"
		dstabspath = os.path.join(HOUSE_DIRECTORY, dstfilepath)
		print 'dstabspath', dstabspath
		fakedir = '/'.join(dstabspath.split('/')[:-1])
		print 'fakedir:', fakedir
		if not os.path.exists(fakedir):
			os.makedirs(fakedir)
		shutil.copy(fakeabspath, dstabspath)

	return Completed(user_pk)

def copydir(files, inodes, dstdir, srcdir, username, user_pk, curdir):
	if len(srcdir) == 1:
		if srcdir[0] == "." :
			srcpath = curdir
		elif srcdir[0] == '..':
			srcpath = curdir[:-1]
		else:
			srcpath = curdir
	else:
		_, srcpath, status = TravserDir(files, inodes, curdir, srcdir[:-1])
		if status == PERMISSION_DENIED:
			return PermsDenied(user_pk)
		elif status == WRONG_PATH:
			return WrongPath(user_pk)
	print 'srcpath: ', srcpath

	if len(dstdir) == 1:
		if dstdir[0] == "." or dstdir[0] == '..':
			return NothingHappen(user_pk)
		else:
			dstpath = curdir
	else:
		_, dstpath, status = TravserDir(files, inodes, curdir, dstdir[:-1], WRITE)
		if status == PERMISSION_DENIED:
			return PermsDenied(user_pk)
		elif status == WRONG_PATH:
			return WrongPath(user_pk)
	print 'dstpath: ', dstpath

	srcpathstr = "/".join(srcpath)
	print 'srcpath: ', srcpathstr
	if srcdir[-1] != '.' and srcdir[-1] != '..':
		srcfilepath = os.path.join(srcpathstr, srcdir[-1])
	else:
		srcfilepath = os.path.join(srcpathstr, '')
	srcabspath = os.path.join(HOUSE_DIRECTORY, srcfilepath)
	print 'srcabspath', srcabspath

	dstpathstr = "/".join(dstpath)
	print 'dstdstpath: ', dstpathstr
	dstfilepath = os.path.join(dstpathstr, dstdir[-1])
	dstabspath = os.path.join(HOUSE_DIRECTORY, dstfilepath)
	print 'dstabspath', dstabspath
	dstpath_copy = copy.copy(dstpath)
	

	# inode
	if srcfilepath not in inodes.keys():
		return WrongPath(user_pk)
	if inodes[srcfilepath].type != DIR:
		return COPYWrong(user_pk)
	NewInode = copy.deepcopy(inodes[srcfilepath])
	NewInode.filename = dstdir[-1]
	print 'newfile:', NewInode.filename
	inodes[dstfilepath] = copy.deepcopy(NewInode)

	for file in inodes.keys():
		if file.startswith(srcfilepath) and len(file) != len(srcfilepath):
			NewInode = copy.deepcopy(inodes[file])
			newfile = file.replace(srcfilepath, dstfilepath)
			inodes[newfile] = NewInode
	print inodes

	# files
	if srcdir[-1] != '.' and srcdir[-1] != '..':
		srcpath.append(srcdir[-1])
		print 'srcpath out:', srcpath
	dstpath_copy.append(dstdir[-1])
	print 'dstpath out:', dstpath_copy
	if DirToDir(files, srcpath, dstpath_copy) == WRONG_PATH:
		return WrongPath(user_pk)
		
	print 'dstfilepath:', dstfilepath
	inodes[dstfilepath].filename = dstdir[-1]
	print 'newfilename:',inodes[dstfilepath].filename
		
	# untrusted file system
	# try:
	dstabspath = os.path.join(HOUSE_DIRECTORY, dstfilepath)
	print 'dstabspath', dstabspath
	fakedir = '/'.join(dstabspath.split('/')[:-1])
	print 'fakedir:', fakedir
	if not os.path.exists(fakedir):
		os.makedirs(fakedir)
	shutil.copytree(srcabspath, dstabspath)
	# except:
		# return OSError(user_pk)

	return Completed(user_pk)

def movefile(files, inodes, dst, src, username, user_pk, curdir):
	if len(src) == 1:
		if src[0] == "." or src[0] == '..':
			return NothingHappen(user_pk)
		else:
			srcpath = curdir
	else:
		_, srcpath, status = TravserDir(files, inodes, curdir, src[:-1])
		if status == PERMISSION_DENIED:
			return PermsDenied(user_pk)
		elif status == WRONG_PATH:
			return WrongPath(user_pk)
	print 'srcpath: ', srcpath

	if len(dst) == 1:
		if dst[0] == "." :
			dstpath = curdir
		elif dst[0] == '..':
			dstpath = curdir[:-1]
		else:
			dstpath = curdir
	else:
		_, dstpath, status = TravserDir(files, inodes, curdir, dst[:-1], WRITE)
		if status == PERMISSION_DENIED:
			return PermsDenied(user_pk)
		elif status == WRONG_PATH:
			return WrongPath(user_pk)
	print 'dstpath: ', dstpath

	srcpathstr = "/".join(srcpath)
	print 'srcpath: ', srcpathstr
	srcfilepath = os.path.join(srcpathstr, src[-1])
	srcabspath = os.path.join(HOUSE_DIRECTORY, srcfilepath)
	print 'srcabspath', srcabspath
	if not os.path.exists(srcabspath):
		return WrongPath(user_pk)
	srcpath_copy = copy.copy(srcpath)

	dstpathstr = "/".join(dstpath)
	print 'dstdstpath: ', dstpathstr
	if dst[-1] != '..' and dst[-1] != '.':
		dstfilepath = os.path.join(dstpathstr, dst[-1])
		dstpath.append(dst[-1])
	else:
		dstfilepath = os.path.join(dstpathstr, '')
	
	# inode
	if srcfilepath not in inodes.keys():
		return WrongPath(user_pk)
	elif inodes[srcfilepath].type == DIR:
		print "src is DIR"
		if dstfilepath in inodes.keys() and inodes[dstfilepath].type == DIR:
			print "mv dir to dir(including the src dir)"
			for file in inodes.keys():
				if file.startswith(srcfilepath):
					NewInode = copy.deepcopy(inodes.pop(file))
					print 'file:',file
					totalpath = os.path.join(dstfilepath, src[-1])
					if len(file) != len(srcfilepath):
						totalpath = os.path.join(totalpath, file[len(srcfilepath)+1:])
					print "totalpath:", totalpath
					inodes[totalpath] = NewInode
			# file operations
			srcpath_copy.append(src[-1])
			print 'srcpath_copy:', srcpath_copy
			if MoveDir2Dir(files, srcpath_copy, dstpath) == WRONG_PATH:
				return WrongPath(user_pk)
			# untrust file server								
			dstabspath = os.path.join(HOUSE_DIRECTORY, dstfilepath)
			print 'dstabspath', dstabspath
			fakedir = '/'.join(dstabspath.split('/')[:-1])
			print 'fakedir:', fakedir
			if not os.path.exists(fakedir):
				os.makedirs(fakedir)
			print 'srcabspath:',srcabspath
			shutil.move(srcabspath, dstabspath)
		elif dstfilepath in inodes.keys() and inodes[dstfilepath].type == FILE:
			return MOVEWrong(user_pk)
		else:
			print "rename dir"
			old = inodes.pop(srcfilepath)
			old.chfilename(dst[-1])
			inodes[dstfilepath] = old
			for file in inodes.keys():
				if file.startswith(srcfilepath):
					NewInode = copy.deepcopy(inodes.pop(file))
					newfile = file.replace(srcfilepath, dstfilepath)
					inodes[newfile] = NewInode
			# file operations
			srcpath_copy.append(src[-1])
			print 'srcpath_copy:', srcpath_copy
			print 'dstpath', dstpath
			if Rename(files, srcpath_copy, dstpath) == WRONG_PATH:
				return WrongPath(user_pk)
			# untrust file server				
			dstabspath = os.path.join(HOUSE_DIRECTORY, dstfilepath)
			print 'dstabspath', dstabspath
			fakedir = '/'.join(dstabspath.split('/')[:-1])
			print 'fakedir:', fakedir
			if not os.path.exists(fakedir):
				os.makedirs(fakedir)
			print 'srcabspath:',srcabspath
			shutil.move(srcabspath, dstabspath)
	elif inodes[srcfilepath].type == FILE:
		print "src is FILE"
		if dstfilepath not in inodes.keys():
			print "rename file"
			old = inodes.pop(srcfilepath)
			old.chfilename(dst[-1])
			inodes[dstfilepath] = old
			# file operations
			srcpath_copy.append(src[-1])
			print 'srcpath_copy:', srcpath_copy
			print 'dstpath', dstpath
			if Rename(files, srcpath_copy, dstpath) == WRONG_PATH:
				return WrongPath(user_pk)
			# untrust file server				
			dstabspath = os.path.join(HOUSE_DIRECTORY, dstfilepath)
			print 'dstabspath', dstabspath
			fakedir = '/'.join(dstabspath.split('/')[:-1])
			print 'fakedir:', fakedir
			if not os.path.exists(fakedir):
				os.makedirs(fakedir)
			print 'srcabspath:',srcabspath
			shutil.move(srcabspath, dstabspath)
		elif dstfilepath in inodes.keys() and inodes[dstfilepath].type == DIR:
			print "mv file to dir"
			old = inodes.pop(srcfilepath)
			NewInode = copy.deepcopy(old)
			totalpath = os.path.join(dstfilepath, src[-1])
			print 'totalpath:', totalpath
			inodes[totalpath] = NewInode
			# file operations
			srcpath_copy.append(src[-1])
			print 'srcpath_copy:', srcpath_copy
			if MoveFile2Dir(files, srcpath_copy, dstpath) == WRONG_PATH:
				return WrongPath(user_pk)
			# untrust file server				
			dstabspath = os.path.join(HOUSE_DIRECTORY, dstfilepath)
			print 'dstabspath', dstabspath
			fakedir = copy.copy(dstabspath)
			print 'fakedir:', fakedir
			if not os.path.exists(fakedir):
				os.makedirs(fakedir)
			
			temp = src[-1].split('/')[0]
			fakesrc = '/'.join(srcpath_copy[:-1])
			fakesrc = '/'.join([fakesrc, temp])
			fakeabspath = os.path.join(HOUSE_DIRECTORY, fakesrc)
			print 'fakeabspath:', fakeabspath
			shutil.move(fakeabspath, dstabspath)
		else:
			return MOVEWrong(user_pk)

	return Completed(user_pk)

def SetObjPerm(files, inodes, obj, perm, username, user_pk, curdir):
	curdir, path, status = TravserDir(files, inodes, curdir, obj)
	if status == PERMISSION_DENIED:
		return PermsDenied(user_pk)
	elif status == WRONG_PATH:
		return WrongPath(user_pk)

	pathstr = "/".join(path)
	print 'pathstr', pathstr

	if pathstr not in inodes.keys():
		return WrongPath(user_pk)

	filenode = inodes[pathstr]
	oldperm = copy.copy(filenode.perm)
	print 'oldperm:', filenode.perm

	intperm = 0
	if perm.upper() == "R":
		intperm = READ
	elif perm.upper() == "W":
		intperm = WRITE
	elif perm.upper() == "E":
		intperm = EXEC
	elif perm.upper() == "U":
		intperm = 0
	else:
		repo = {}
		repo["status"] = 'FALSE'
		repo["data"] = "illegal perm!"
		msg = json.dumps(repo)
		standard_packet = CreateStandardPacket(user_pk, msg)
		return standard_packet


	filenode.setperm(intperm)

	print 'Newperm:', filenode.perm

	repo = {}
	repo["status"] = 'OK'
	repo["data"] = {'oldperm':oldperm, 'newperm':perm}
	msg = json.dumps(repo)
	standard_packet = CreateStandardPacket(user_pk, msg)
	return standard_packet

def upLoad(files, inodes, dst, fn, content, username, user_pk, curdir):
	path = curdir
	filename = dst
	filename.append(fn)
	print 'filename', filename
	if len(filename) == 1:
		if filename[0] == "." or filename[0] == '..':
			return NothingHappen(user_pk)
		else:
			path = curdir
	else:
		_, path, status = TravserDir(files, inodes, curdir, filename[:-1])
		if status == PERMISSION_DENIED:
			return PermsDenied(user_pk)
		elif status == WRONG_PATH:
			return WrongPath(user_pk)

	pathstr = "/".join(path)
	print 'path', pathstr

	try:
		if inodes[pathstr].type == FILE:
			print "dst_type:", inodes[pathstr].type
			return WrongPath(user_pk)
	except:
		return WrongPath(user_pk)


	filepath = os.path.join(pathstr, filename[-1])
	abspath = os.path.join(HOUSE_DIRECTORY, filepath)
	print 'abspath', abspath


	# inode files
	NewInode = Inode(username, filename[-1])
	if filepath not in inodes.keys():
		inodes[filepath] = NewInode
	print inodes

	path.append(filename[-1])
	if InsertIntoFile(files, path) == WRONG_PATH:
		return WrongPath(user_pk)

	fakedir = '/'.join(abspath.split('/')[:-1])
	print 'fakedir', fakedir
	# if not os.path.exists(fakedir):
		# os.makedirs(fakedir)
	# try:
	# os.mknod(abspath)
	f = open(abspath, 'w')
	f.write(content)
	f.close()
	# except:
		# return Duplicated(user_pk)

	return Completed(user_pk)

def DownLoad(files, inodes, filename, username, user_pk, curdir):
	if len(filename) == 1:
		if filename[0] == "." or filename[0] == '..':
			return NothingHappen(user_pk)
		else:
			path = curdir
	else:
		_, path, status = TravserDir(files, inodes, curdir, filename[:-1])
		if status == PERMISSION_DENIED:
			return PermsDenied(user_pk)
		elif status == WRONG_PATH:
			return WrongPath(user_pk)

	pathstr = "/".join(path)
	print 'path', pathstr

	filepath = os.path.join(pathstr, filename[-1])

	try:
		if inodes[filepath].type != FILE:
			print "dst_type:", inodes[pathstr].type
			return WrongPath(user_pk)
	except:
		return WrongPath(user_pk)

	filepath = os.path.join(pathstr, filename[-1])
	abspath = os.path.join(HOUSE_DIRECTORY, filepath)
	print 'abspath', abspath

	if not os.path.exists(abspath):
		print 'fake path does not exist!'
		return WrongPath(user_pk)

	f = open(abspath, 'r')
	content = f.read()
	f.close()

	repo = {}
	repo["status"] = "OK"
	repo["data"] = {"content": content, 'filename':filename[-1]}
	msg = json.dumps(repo)
	standard_packet = CreateStandardPacket(user_pk, msg)
	return standard_packet

