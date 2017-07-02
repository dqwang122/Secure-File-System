from Crypto.PublicKey import RSA
import base64
import json
import chunk_encrypt as c


def CreateStandardPacket(user_pk, msg):
	print user_pk
	ciphertxt = c.encrypt(user_pk, msg, False)
	ciphertxts = json.dumps({"ciphertxt": ciphertxt})
	length = len(ciphertxts)
	packet = str(length) + '|' + ciphertxts
	return packet

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
	print "Using rm to delete dir"
	repo = {}
	repo["status"] = 'False'
	repo["data"] = "You are deleting a directory. If you must, you can try rm -r [dir]"
	msg = json.dumps(repo)
	standard_packet = CreateStandardPacket(user_pk, msg)
	return standard_packet
	
def COPYDENIED(user_pk):
	print "Using cp to copy dir"
	repo = {}
	repo["status"] = 'False'
	repo["data"] = "You are copying a directory. If you must, you can try cp -r [dir]"
	msg = json.dumps(repo)
	standard_packet = CreateStandardPacket(user_pk, msg)
	return standard_packet
	
def COPYWrong(user_pk):
	print "Using cp -r to copy file"
	repo = {}
	repo["status"] = 'False'
	repo["data"] = "You are copying a file. If you must, you can try cp without -r"
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