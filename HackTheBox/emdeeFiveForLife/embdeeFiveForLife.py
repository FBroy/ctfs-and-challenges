import requests
import hashlib


req = requests.session()
content = req.get("http://46.101.39.64:30563").text
content = content[167:187]
#print(content)
content = hashlib.md5(content.encode())
hashed = content.hexdigest()
#print(hashed)
data = {"hash": hashed}
result = req.post("http://46.101.39.64:30563", data)
print(result.text)