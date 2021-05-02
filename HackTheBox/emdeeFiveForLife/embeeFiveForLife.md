Date: 2021-05-02

Category: Web

## Description

Can you encrypt fast enough?

On the given URL, you find a small submit form and a random string. The website asks to submit the MD5-hashed version of the string. However, when you hash the script manually, the website says. that you're too slow. This means, that we need to write a script to automate it and make it faster.

## Complete writeup

I wrote a Python script, that automates the process of hashing and submitting the script.

So I used 'requests' to get the contents of the html of the page, to extract the string.

```Python
content = requests.get("http://46.101.39.64:30563").text
content = content[167:187]
```

With the string extracted, it was time to MD5-hash it.

```Python
content = hashlib.md5(content.encode())
hashed = content.hexdigest()
```

Now that I had the MD5-hash of the string, I just needed to submit it, which was also done with 'requests'.

```Python
result = requests.post("http://46.101.39.64:30563", hashed)
```

The result of this POST request however, was not what I wanted to see. The response I got told me I was too slow. So I started to think and analyzed my code again. Then I checked the documentation of 'requests' and saw, that you could make an active session and then use the same session to make both the GET and the POST request. With the hope, that this would be faster, I tried again.

No luck, the site told me that I was too slow again...

So I looked up how exactly a response to a web-form should be submitted and found out, that they are submitted in dictionaries. Given that the name of the input field was "hash", I picked that as the key of the dictionary and the value being the MD5-hash of the string. With the POST request changed, I tried again:

```Python
data = {"hash": hashed}
result = req.post("http://46.101.39.64:30563", data)
```

And Bingo, the response contained the flag and the challenge was completed!

```HTML
<html>
<head>
<title>emdee five for life</title>
</head>
<body style="background-color:powderblue;">
<h1 align='center'>MD5 encrypt this string</h1><h3 align='center'>SY7X9Jo56NtBvIgYmydb</h3><p align='center'>HTB{N1c3_ScrIpt1nG_B0i!}</p><center><form action="" method="post">
<input type="text" name="hash" placeholder="MD5" align='center'></input>
</br>
<input type="submit" value="Submit"></input>
</form></center>
</body>
</html>
```

## Final Solution

```Python
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
```