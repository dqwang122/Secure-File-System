import os
import sys

def usage():
	print """
    help			print the help
    quit			quit the file system
	
    #Filesystem methods#
    cd				change the directory
    pwd				print current directory
    ls				list file under the directory
    mkdir			create a new directory
    touch			create a new file
    rm				remove a file or directory(-r)
    cp [src] [dst]		copy src to dst (directory with -r)
    mv [src] [dst]		move or rename src to dst (file or directory)
    chmod [dst] [mode]		set perm for file or directory
    
    #File methods#
    read			read file from remote file server
    write [filename] [data]	write data to file of remote file server
	
    #Other methods#
    upload			upload file to remote server
    download			download file from remote server
    share -f -u [mode]		share with others

	"""

def Unfinish():
	print "This function has not been complete..."