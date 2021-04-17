import socket              
s = socket.socket()  
#for test run server.py and change port to 3105 and address to localhost        
port = 53               
s.connect(('8.8.8.8', port))  
z = 'Your string'
s.sendall(z.encode())

s.close()
