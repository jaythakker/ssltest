import os
import string
import sys

host_name = sys.argv[1]

def get_cipher(c):
	filtered_string = filter(lambda x: x in string.printable, c)
	newstr = filtered_string.replace("[0m", "")
	return newstr;

cmd='pysslscan scan --scan=server.ciphers --scan=vuln.heartbleed --report=term --ssl2 --ssl3 --tls10 --tls11 --tls12 '+host_name
s = os.popen(cmd).read()
cipher = get_cipher(s)
# convert to string array
ciphers = cipher.split('\n')

print("\r")
welcome="SSL Configuration results for "+host_name+" domain"
print welcome
print("\r")

print("Following are the Weak Ciphers used by Server:")
print("\r")

poodle_check = False
check = False
cipher = None
beast=False
heartbleed=False
p=False

#print type(ciphers)

for i in ciphers:
	if check==False:
		if "TLSv10" in i:
			beast=True
			check=True
	if "DES" in i:
		p=True
		print i
	if "IDEA" in i:
		p=True
		print i
	if "RC4" in i:
		p=True
		print i
	if "CBC" in i:
		p=True
		print i
	if p==False:
		if "TLS_RSA" in i:
			p=False
			print i
	if "SSLv3" in i:
		if "CBC" in i:
			poodle_check=True
	if "Vulnerable: yes" in i:
		heartbleed=True

if beast:
	print("\r")
	print "TLS/SSL server uses TLSv1.0 which is vulnerable to BEAST attack"

if poodle_check:
	print("\r")
	print "TLS/SSL uses SSLv3 with CBC mode which is vulnerable to POODLE attack"

if heartbleed:
	print("\r")
	print "TLS/SSL Server is vulnerable to Heartbleed attack"
