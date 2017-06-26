# def Login(client, address):
	client.settimeout(500)
	# while 1:
		# try:
			# buf = client.recv(MAXBUFF)
		# except:
			# client.close()
		# if not buf or buf == "q":
			# print address, ' close the connect'
			# break
		# print 'Received:', buf, 'from', address
		# client.send(buf)
	# client.close()	
	
	
# s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# s.bind((HOST,PORT))		#server ip 
# s.listen(MAXCONN)

# while True:
# client, address = s.accept()
# print 'Connected by', address
# thread = threading.Thread(target=Login, args=(client, address))