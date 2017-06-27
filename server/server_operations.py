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

def PacketERR(user_pk):
	print "The packet has been distroyed"
	repo = {}
	repo["status"] = 'False'
	repo["data"] = "PACKET INCOMPLETED"
	msg = json.dumps(repo)
	standard_packet = CreateStandardPacket(user_pk, msg)
	return standard_packet

def NothingHappen(user_pk):
	print "Nothing happens"
	repo = {}
	repo["status"] = 'False'
	repo["data"] = "Nothing happens"
	msg = json.dumps(repo)
	standard_packet = CreateStandardPacket(user_pk, msg)
	return standard_packet

def Duplicated(user_pk):
	print "The file has existed"
	repo = {}
	repo["status"] = 'False'
	repo["data"] = "The file has existed!"
	msg = json.dumps(repo)
	standard_packet = CreateStandardPacket(user_pk, msg)
	return standard_packet

def Completed(user_pk):
	print "Complete successfully"
	repo = {}
	repo["status"] = 'OK'
	repo["data"] = "Success"
	msg = json.dumps(repo)
	standard_packet = CreateStandardPacket(user_pk, msg)
	return standard_packet

def PermsDenied(user_pk):
	print "Permissions Denied"
	repo = {}
	repo["status"] = 'False'
	repo["data"] = "You don't have access to this dir!"
	msg = json.dumps(repo)
	standard_packet = CreateStandardPacket(user_pk, msg)
	return standard_packet

def WrongPath(user_pk):
	print "The file or directory does not exist!"
	repo = {}
	repo["status"] = 'False'
	repo["data"] = "The file or directory does not exist!"
	msg = json.dumps(repo)
	standard_packet = CreateStandardPacket(user_pk, msg)
	return standard_packet

def DELETEDENIED(user_pk):
	print "Using rm to delete file"
	repo = {}
	repo["status"] = 'False'
	repo["data"] = "You are deleting a directory. If you must, you can try rm -r [dir]"
	msg = json.dumps(repo)
	standard_packet = CreateStandardPacket(user_pk, msg)
	return standard_packet

def OSError(user_pk):
	print "OS operations error"
	repo = {}
	repo["status"] = 'False'
	repo["data"] = "Something to do with OS operations"
	msg = json.dumps(repo)
	standard_packet = CreateStandardPacket(user_pk, msg)
	return standard_packet

def InsertIntoFile(files, filepath):
	curdir = files
	for dir in filepath[:-1]:
		if dir not in curdir.keys():
			return WRONG_PATH
		curdir = curdir[dir]
	curdir[filepath[-1]] = FILETYPR
	return True

def CopyIntoFile(files, srcfilename, dstpath):
	curdir = files
	for dir in dstpath[:-1]:
		if dir not in curdir.keys():
			return WRONG_PATH
		curdir = curdir[dir]
	# for dst as dir
	if dstpath[-1] in curdir.keys() and curdir[dstpath[-1]] != FILETYPR :
		curdir = curdir[dstpath[-1]]
	print 'curdir', curdir
	print 'srcfilename', srcfilename
	curdir[srcfilename] = FILETYPR
	print 'curdir', curdir
	print 'files', files

	return True

def DirToDir(files, srcpath, dstpath):
	curdir = files
	for dir in dstpath[:-1]:
		if dir not in curdir.keys():
			return WRONG_PATH
		curdir = curdir[dir]
	if dstpath[-1] not in curdir.keys():
		curdir[dstpath[-1]] = {}
	dstdir = curdir[dstpath[-1]]

	srccurdir = files
	for dir in srcpath:
		if dir not in curdir.keys():
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
		print 'curdir:', curdir
	curdir[filepath[-1]] = {}
	return True


def TravserDir(files, inodes, curpath, dstpath):
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
		travserpaths.extend(dstpath)
	else:
		travserpaths.extend(curpath)
		travserpaths.extend(dstpath)

	print "currentpaths: ", curpath
	print "dstpaths: ", dstpath
	print "travserpaths: ", travserpaths

	cnt = 0
	for dir in travserpaths:
		if dir not in curdir.keys():
			return curdir, travserpaths, WRONG_PATH
		else:
			curpathstr = '/'.join(travserpaths[:cnt+1])
			print 'curpathstr', curpathstr
			if curpathstr not in inodes.keys():
				return curdir, travserpaths, WRONG_PATH
			if not inodes[curpathstr].checkperm(READ):
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
		print curlistf
		for file in curlistf:
			total_path = os.path.join(curpathstr,file)
			# print total_path
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
	path = curdir
	if len(filename) == 1:
		if filename[0] == "." or filename[0] == '..':
			return NothingHappen(user_pk)
		else:
			path = curdir
	else:
		_, path, status = TravserDir(files, inodes, curdir, filename[:-1])
		if status == PERMISSION_DENIED:
			return  PermsDenied(user_pk)
		elif status == WRONG_PATH:
			return WrongPath(user_pk)

	pathstr = "/".join(path)
	print 'path', pathstr
	filepath = os.path.join(pathstr, filename[-1])
	abspath = os.path.join(HOUSE_DIRECTORY, filepath)
	print 'abspath', abspath

	fakedir = '/'.join(abspath.split('/')[:-1])
	print 'fakedir', fakedir
	if not os.path.exists(fakedir):
		os.makedirs(fakedir)
	try:
		os.mknod(abspath)
	except:
		return Duplicated(user_pk)

	# inode files
	NewInode = Inode(username, filename[-1])
	if filepath not in inodes.keys():
		inodes[filepath] = NewInode
	print inodes

	path.append(filename[-1])
	if InsertIntoFile(files, path) == WRONG_PATH:
		return WrongPath(user_pk)

	return Completed(user_pk)

def deletefile(files, inodes, filename, username, user_pk, curdir):
	path = curdir
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
	abspath = os.path.join(HOUSE_DIRECTORY, filepath)
	print 'abspath', abspath

	# inode files
	if filepath not in inodes.keys():
		WrongPath(user_pk)
	else:
		inodes.pop(filepath)
	print inodes

	path.append(filename[-1])
	check = DeleteFromFile(files, path)
	if check == WRONG_PATH:
		return WrongPath(user_pk)
	elif check == DELETEDIR_ERROR:
		return DELETEDENIED(user_pk)

	fakedir = '/'.join(abspath.split('/')[:-1])
	print fakedir
	if not os.path.exists(fakedir):
		return WrongPath(user_pk)
	try:
		os.remove(abspath)
	except:
		return DELETEDENIED(user_pk)

	return Completed(user_pk)


def createnewdir(files, inodes, dstdir, username, user_pk, curdir):
	path = curdir
	if len(dstdir) == 1:
		if dstdir[0] == "." or dstdir[0] == '..':
			return NothingHappen(user_pk)
		else:
			path = curdir
	else:
		_, path, status = TravserDir(files, inodes, curdir, dstdir[:-1])
		if status == PERMISSION_DENIED:
			return  PermsDenied(user_pk)
		elif status == WRONG_PATH:
			return WrongPath(user_pk)

	pathstr = "/".join(path)
	print 'path', pathstr
	filepath = os.path.join(pathstr, dstdir[-1])
	abspath = os.path.join(HOUSE_DIRECTORY, filepath)
	print 'abspath', abspath

	fakedir = '/'.join(abspath.split('/')[:-1])
	print 'fakedir', fakedir
	if not os.path.exists(fakedir):
		os.makedirs(abspath)
	# try:
	# 	os.mknod(abspath)
	# except:
	# 	return Duplicated(user_pk)

	# inode files
	NewInode = Inode(username, dstdir[-1], DIR)
	if filepath not in inodes.keys():
		inodes[filepath] = NewInode
	else:
		return Duplicated(user_pk)
	print inodes

	path.append(dstdir[-1])
	if CreateDirInto(files, path) == WRONG_PATH:
		return WrongPath(user_pk)
	return Completed(user_pk)

def deletedir(files, inodes, dstdir, username, user_pk, curdir):
	path = curdir
	if len(dstdir) == 1:
		if dstdir[0] == "." or dstdir[0] == '..':
			return NothingHappen(user_pk)
		else:
			path = curdir
	else:
		_, path, status = TravserDir(files, inodes, curdir, dstdir[:-1])
		if status == PERMISSION_DENIED:
			return PermsDenied(user_pk)
		elif status == WRONG_PATH:
			return WrongPath(user_pk)

	pathstr = "/".join(path)
	print 'path', pathstr
	filepath = os.path.join(pathstr, dstdir[-1])
	abspath = os.path.join(HOUSE_DIRECTORY, filepath)
	print 'abspath', abspath

	# inode files
	dirpath = os.path.join(pathstr, dstdir[-1])
	print 'dirpath: ', dirpath
	if dirpath not in inodes.keys():
		WrongPath(user_pk)
	else:
		inodes.pop(dirpath)
	for file in inodes.keys():
		if file.startswith(dirpath):
			inodes.pop(file)
	print inodes

	path.append(dstdir[-1])
	check = DeleteFromDir(files, path)
	if check == WRONG_PATH:
		return WrongPath(user_pk)

	fakedir = '/'.join(abspath.split('/')[:-1])
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
		_, dstpath, status = TravserDir(files, inodes, curdir, dst[:-1])
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

	dstpathstr = "/".join(dstpath)
	print 'dstdstpath: ', dstpathstr
	if dst[-1] != '.' and dst[-1] != '..':
		dstfilepath = os.path.join(dstpathstr, dst[-1])
	else:
		dstfilepath = os.path.join(dstpathstr, '')
	dstabspath = os.path.join(HOUSE_DIRECTORY, dstfilepath)
	print 'dstabspath', dstabspath

	# inode files
	if dst[-1] != '.' and dst[-1] != '..':
		dstpath.append(dst[-1])

	try:
		NewInode = copy.deepcopy(inodes[srcfilepath])

		curdir = files
		for dir in dstpath[:-1]:
			if dir not in curdir.keys():
				return WRONG_PATH
			curdir = curdir[dir]
		# for dst as dir
		if dstpath[-1] in curdir.keys() and curdir[dstpath[-1]] != FILETYPR:
			dstfile = os.path.join(dstfilepath, src[-1])
			inodes[dstfile] = NewInode
		else:
			inodes[dstfilepath] = NewInode
	except:
		WrongPath(user_pk)
	print inodes

	srcpath.append(src[-1])
	if CopyIntoFile(files, src[-1], dstpath) == WRONG_PATH:
		return WrongPath(user_pk)

	if not os.path.exists(srcabspath):
		WrongPath(user_pk)
	try:
		shutil.copy(srcabspath, dstabspath)
	except:
		return OSError(user_pk)

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
		return NothingHappen(user_pk)
	else:
		_, dstpath, status = TravserDir(files, inodes, curdir, dstdir[:-1])
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
	dstfilepath = os.path.join(dstpathstr, '')
	dstabspath = os.path.join(HOUSE_DIRECTORY, dstfilepath)
	print 'dstabspath', dstabspath

	if not os.path.exists(srcabspath):
		WrongPath(user_pk)
	if os.path.exists(dstabspath):
		DELETEDENIED(user_pk)
	try:
		shutil.copytree(srcabspath, dstabspath)
	except:
		return OSError(user_pk)

	# inode files
	try:
		NewInode = copy.deepcopy(inodes[srcfilepath])
		inodes[dstfilepath] = NewInode
	except:
		WrongPath(user_pk)
	for file in inodes.keys():
		if file.startswith(srcfilepath):
			NewInode = copy.deepcopy(inodes[file])
			newfile = file.replace(srcfilepath, dstfilepath)
			inodes[newfile] = NewInode
	print inodes

	if srcdir[-1] != '.' and srcdir[-1] != '..':
		srcpath.append(srcdir[-1])
	if DirToDir(files, srcpath, dstpath) == WRONG_PATH:
		return WrongPath(user_pk)

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
		_, dstpath, status = TravserDir(files, inodes, curdir, dst[:-1])
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

	tempsrcpath = copy.deepcopy(srcpath)

	dstpathstr = "/".join(dstpath)
	print 'dstdstpath: ', dstpathstr
	if dst[-1] != '.' and dst[-1] != '..':
		dstfilepath = os.path.join(dstpathstr, dst[-1])
	else:
		dstfilepath = os.path.join(dstpathstr, '')
	dstabspath = os.path.join(HOUSE_DIRECTORY, dstfilepath)
	print 'dstabspath', dstabspath

	if dst[-1] != '.' and dst[-1] != '..':
		dstpath.append(dst[-1])

	# inode files
	try:
		NewInode = inodes.pop(srcfilepath)

		curdir = files
		for dir in dstpath[:-1]:
			if dir not in curdir.keys():
				return WRONG_PATH
			curdir = curdir[dir]
		# for dst as dir
		print 'try curdir:', curdir
		print 'try dstpath[-1]', dstpath[-1]
		if dstpath[-1] in curdir.keys() and curdir[dstpath[-1]] != FILETYPR:
			dstfile = os.path.join(dstfilepath, src[-1])
			print 'dstfile', dstfile
			inodes[dstfile] = NewInode
		else:
			inodes[dstfilepath] = NewInode
	except:
		WrongPath(user_pk)

	tempsrcpath.append(src[-1])
	print "src[-1]", src[-1]
	print "out tempsrcpath:", tempsrcpath
	print 'outsrcpath:', srcpath
	if CopyIntoFile(files, src[-1], dstpath) == WRONG_PATH:
		return WrongPath(user_pk)

	DeleteFromFile(files, tempsrcpath)

	if not os.path.exists(srcabspath):
		WrongPath(user_pk)
	try:
		shutil.move(srcabspath, dstabspath)
	except:
		return OSError(user_pk)

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
	oldperm = copy.copy(filenode.getperm())
	print 'oldperm:', filenode.getperm()

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

	print 'Newperm:', filenode.getperm()

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
		if inodes[pathstr].gettype() == FILE:
			print "dst_type:", inodes[pathstr].gettype()
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
		if inodes[filepath].gettype() != FILE:
			print "dst_type:", inodes[pathstr].gettype()
			return WrongPath(user_pk)
	except:
		return WrongPath(user_pk)

	filepath = os.path.join(pathstr, filename[-1])
	abspath = os.path.join(HOUSE_DIRECTORY, filepath)
	print 'abspath', abspath

	if not os.path.exists(abspath):
		WrongPath(user_pk)
	try:
		f = open(abspath, 'r')
		content = f.read()
		f.close()
	except:
		return Duplicated(user_pk)

	repo = {}
	repo["status"] = "OK"
	repo["data"] = {"content": content, 'filename':filename[-1]}
	msg = json.dumps(repo)
	standard_packet = CreateStandardPacket(user_pk, msg)
	return standard_packet

