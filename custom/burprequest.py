import requests
from requests.api import request


class BurpReq:
	"""
	Interface for making HTTP request from burp suite headers.
	copy the full request from burp suite and pass it as the message param
	"""
# POST /login HTTP/1.1
# Host: aca71f581fa57dccc08960a2009b0032.web-security-academy.net
# Cookie: session=lK3H4kurlhL79K9jJ6k25t1xZzZy1uBS
# Content-Length: 30
# Cache-Control: max-age=0
# Sec-Ch-Ua: ";Not A Brand";v="99", "Chromium";v="94"
# Sec-Ch-Ua-Mobile: ?0
# Sec-Ch-Ua-Platform: "Windows"
# Upgrade-Insecure-Requests: 1
# Origin: https://aca71f581fa57dccc08960a2009b0032.web-security-academy.net
# Content-Type: application/x-www-form-urlencoded
# User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36
# Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
# Sec-Fetch-Site: same-origin
# Sec-Fetch-Mode: navigate
# Sec-Fetch-User: ?1
# Sec-Fetch-Dest: document
# Referer: https://aca71f581fa57dccc08960a2009b0032.web-security-academy.net/login
# Accept-Encoding: gzip, deflate
# Accept-Language: en-US,en;q=0.9
# Connection: close

# username=wiener&password=peter

	METHODS = ['GET', 'OPTIONS', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']

	full_header = None
	method      = None
	path        = None
	host        = None
	cookies     = None
	data        = None
	# url         = None
	# params      = None
	headers     = None

	def __init__(self, message, debug=True) -> None:
		self.full_header = message.split("\n")
		self.debug = debug
		if self.debug:
			print(f'full => {self.full_header}\n\n')

		self.SetMethodAndPath()
		self.SetHost()
		self.SetCookie()
		self.SetData()
		self.SetHeaders()

	def SetMethodAndPath(self):
		self.method, self.path, _ = self.full_header[0].split()
		if self.debug:
			print(f'method: {self.method}, path: {self.path}')
	
	def SetHost(self):
		self.host = self.full_header[1].split()[1]
		if self.debug:
			print(f'host: {self.host}')

	def SetCookie(self):
		"""
		parses `'Cookie: session=Bdvj8qApJ1dFASYePD5cd7THZEa3UItd'`
				to {'session': 'Bdvj8qApJ1dFASYePD5cd7THZEa3UItd'}
		or		 `'Cookie: _ga=GA1.2.1119756560.1634436924; _gid=GA1.2.297382674.1634436924'`
				to {'_ga': 'GA1.2.1119756560.1634436924', '_gid': 'GA1.2.297382674.1634436924'}
		"""
		foo = self.full_header[2].split()

		if "Cookie:" in foo:
			all_cook = foo[1:]
			self.cookies = dict(map(lambda each: each.replace(';', '').split('='), all_cook))

		if self.debug:
			print(f'cookies: {self.cookies}')

	def SetData(self):
		self.data = self.full_header[-1]
		if self.debug:
			print(f'data: {self.data}')

	def SetHeaders(self):
		if self.cookies:
			foo = self.full_header[3:-2]
		else:
			foo = self.full_header[2:-2]
		# print(foo)
		
		header_array = map(lambda x: x.split(': '), foo)
		self.headers = {key:value for key, value in header_array}
		if self.debug:
			print(f'headers: {self.headers}\n')



	def Validate(self, method):
		if method not in self.METHODS:
			raise ValueError

	def MakeRequest(self):
		self.Validate(self.method)
		
		return requests.request(
			self.method,
			'https://' + self.host + self.path,
			data=self.data,
			headers=self.headers,
			cookies=self.cookies
		)

# def Tes:
def Test():
	test  = """GET /pagead/interaction/?ai=CAwYV3KBrYY-sBYWV1gbt_5a4A_WI8NZlpa3jlsUO8C4QASC56I5OYLeEgID0MMgBAqkC_phh4r7HJD6oAwGqBJQCT9A2Gz7xtrVAarhyM0B6hJ_0OkGw5jb2VkIsipXl1pZR7p5QaepY_kXFIaqyMb8nmFJw4Mf4bjqWQuWSpAIBJnRgGILcxUKdMPlhJSNsY-uuMMYXAKdlR02mJU86ZldS65HPJPNewD8FGj-f5CaqDKhN7rc1FcW0d_Dp5Da4IP6VR2aTGWzoAn-A3zvKEcCuQlSQXX6J_Jx6UCCOhrt7sybaxb5as2EahW9153ndIOz-Ahb2o3-DVSL3knGPBgf2vt3TtEv15wI-vYoBcAKh8sNo_YEucupRJOpBNvkVH9dIgV-CWrd5sWZLnVhFSrGsQVG2PzPuEIsWzHyZCEnzj1s805eGP2aPqEcGx7tVzBbPtXH2wATG4-iE2QPgBAOQBgGgBgKAB63Cp9EBqAfw2RuoB_LZG6gHjs4bqAeT2BuoB7oGqAfulrECqAfVyRuoB6a-G6gH89EbqAeW2BuoB6qbsQKoB9-fsQLYBwDSCAcIgGEQARgd8ggbYWR4LXN1YnN5bi02NjYzMzEzNTA4MTA5MTIxgAoDyAsB4AsBgAwBsBPArvQMyBO_wMfeA9gTCtgUAdAVAYAXAQ&sigh=109CoBfbetg&cid=CAQSOwCNIrLMJRCQR3UdE-yNRCvGdqYQswV9XeTijj-8V4NSnFZs9bSdrkXJMsmbD3uaIn1m0o8gOY1-cQg6&label=window_focus&gqid&qqid=CI-KmbrI0PMCFYWK1Qod7b8FNw&fg=1 HTTP/2
Host: googleads.g.doubleclick.net
Cookie: IDE=AHWqTUl6_OwceMOM5MyNMKLO83hW2ahZdHXoEFYaq4jzH9S8Vwj3w7Nn9BrRwvnCUFM; DSID=NO_DATA
Sec-Ch-Ua: ";Not A Brand";v="99", "Chromium";v="94"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: image
Referer: https://8b664f93ce8e268543fb364a7ea12577.safeframe.googlesyndication.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

"""
	# print(test)
	
	res = BurpReq(test)
	data = res.MakeRequest()
	print(data.status_code, data.text)
# a = Req("affaffa")
# print(a.full_header)
if __name__ == "__main__":
	Test()