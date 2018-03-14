import socket
import struct
from datetime import datetime
import os

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 8)
dict = {}

file_txt = open("dos.txt", 'a')
file_txt.writelines("**********")
t1 = str(datetime.now())
file_txt.writelines(t1)
file_txt.writelines("**********")
file_txt.writelines("\n")

print ("Detection start...")

d_val = 10
d_val1 = d_val+10

while True:
	pkt = s.recvfrom(2048)
	ipheader = pkt[0][14:34]
	ip_hdr = struct.unpack("!8sB3s4s4s", ipheader)
	IP = socket.inet_ntoa(ip_hdr[3])

	print ('Source IP: {}'.format(IP))
	if IP in dict:
		dict[IP] = dict[IP]+1
		print (dict[IP])
		print (IP)

		if(dict[IP]>d_val) and (dict[IP]<d_val1):
			line = ("Possible DDoS attack  ")
			file_txt.writelines(line)
			file_txt.writelines(IP)
			file_txt.writelines("\n")
			
		if(dict[IP]>100) and (dict[IP]<200):
			os.system("sudo iptables -A INPUT -s " + IP + " -j DROP")
			print (IP + " has been blocked from your network.")

	else:
		dict[IP] = 10