import requests
import sys

host_name = sys.argv[1]
resp = requests.get("https://cryptoreport.websecurity.symantec.com/chainTester/webservice/validatecerts/json?domain="+host_name+"&port=443")
x = resp.json()
print("\r")
print("Following are the Weak Ciphers used by Server:")
print("\r")
ciphers = x['sslConfig']['cipherSuites']
checker = False
poodle_check = False
index = 0
status = x['sslConfig']['Protocols']['sslv3Status']
	
for i in range(len(ciphers)):
	if "DES" in ciphers[index]:
		checker = True;
	if "IDEA" in ciphers[index]:
		checker = True;
	if "DES" in ciphers[index]:
		print(ciphers[index])
	if "IDEA" in ciphers[index]:
		print(ciphers[index])
	if "RC4" in ciphers[index]:
		print(ciphers[index])
	if checker==False:
		if "TLS_RSA" in ciphers[index]:
			print(ciphers[index])
	if ("CBC" in ciphers[index] and (status==True)):
		poodle_check = True;
	index += 1
	
print("\r")
print("SSL is affected with following Vulnerabilities:")
print("\r")
print("HEARTBLEED Vulnerable:",x['sslConfig']['heartbleed'])
if poodle_check:
	print("('POODLE (SSLv3) Vulnerable:', True)")
else:
	print("('POODLE (SSLv3) Vulnerable:', False)")
print("POODLE (TLS) Vulnerable:",x['sslConfig']['poodletls'])
print("FREAK Vulnerable:",x['sslConfig']['freak'])
print("BEAST Vulnerable:",x['sslConfig']['beast'])
print("CRIME Vulnerable:",x['sslConfig']['crime'])
if checker:
	print("('SWEET32 Vulnerable:', True)")
else:
	print("('SWEET32 Vulnerable:', False)")
