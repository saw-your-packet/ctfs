##### Table of Contents
- [Web](#web)
    - [Leggos](#leggos)
- [Misc](#misc)
    - [Welcome!](#welcome)
    - [16 Home Runs](#16-home-runs)
    - [In a pickle](#in-a-pickle)
    - [Addition](#addition)
- [Forensics](#forensics)
    - [On the spectrum](#on-the-spectrum)
- [Crypto](#crypto)
    - [rot-i](#rot-i)
- [Reversing](#reversing)
    - [Formatting](#formatting)

# <a name="web"></a> Web
## <a name="leggos"></a> Leggos
Points: 100

#### Description
>I <3 Pasta! I won't tell you what my special secret sauce is though!
>
>https://chal.duc.tf:30101

### Solution
We are prompted with a page containing some text and an image. Trying to view the source HTML we notice that we can't do a Right Click. 

![image](https://user-images.githubusercontent.com/38787278/93629841-99251400-f9f1-11ea-82dd-39b9f5773b7a.png)

No problem, we append in the URL `view-source:`, so it becomes `view-source:https://chal.duc.tf:30101/`. Inside the HTML we have a hint saying `<!-- almost there -->`. We open the source code of an imported JS file and we get the flag.

![image](https://user-images.githubusercontent.com/38787278/93630045-fe790500-f9f1-11ea-9364-da4874da9be3.png)

Flag: DUCTF{n0_k37chup_ju57_54uc3_r4w_54uc3_9873984579843}

# <a name="misc"></a> Misc
## <a name="welcome"></a> Welcome
Points: 100

#### Description
>Welcome to DUCTF!
>
>ssh ductf@chal.duc.tf -p 30301
>
>Password: ductf
>
>Epilepsy warning

### Solution
When you connect to the machine a bounch of messages are displayed and you can not execute any command. I tried to `scp` the whole home directory, but the script that displayed the messages on ssh connection was throwing some error. Looking more closely, the flag is displayed among the other messages.

![image](https://user-images.githubusercontent.com/38787278/93637063-a0eab580-f9fd-11ea-8226-6cedbbc13ded.png)

Flag: DUCTF{w3lc0m3_t0_DUCTF_h4v3_fun!}

## <a name="16-home-runs"></a> 16 Home Runs
Points: 100

#### Description
>How does this string relate to baseball in anyway? What even is baseball? And how does this relate to Cyber Security? ¯(ツ)/¯
>
>`RFVDVEZ7MTZfaDBtM19ydW41X20zNG41X3J1bm4xbjZfcDQ1N182NF9iNDUzNX0=`

### Solution
I have no idea about baseball, but I know that the string looks like encoding and it's not base 16 (hex). Base64 deconding it gives us the flag.

Flag: DUCTF{16_h0m3_run5_m34n5_runn1n6_p457_64_b4535}

## <a name="in-a-pickle"></a> In a pickle
Points: 200

#### Description
>We managed to intercept communication between und3rm4t3r and his hacker friends. However it is obfuscated using something. We just can't figure out what it is. Maybe you can help us find the flag?

### Solution
We get a file with the next content:
```text
(dp0
I1
S'D'
p1
sI2
S'UCTF'
p2
sI3
S'{'
p3
sI4
I112
sI5
I49
sI6
I99
sI7
I107
sI8
I108
sI9
I51
sI10
I95
sI11
I121
sI12
I48
sI13
I117
sI14
I82
sI15
I95
sI16
I109
sI17
I51
sI18
I53
sI19
I53
sI20
I52
sI21
I103
sI22
I51
sI23
S'}'
p4
sI24
S"I know that the intelligence agency's are onto me so now i'm using ways to evade them: I am just glad that you know how to use pickle. Anyway the flag is "
p5
s.
```
Looking at this and considering the challenge title is becomes clear that this is a pickled object. I used the next script to unpickle it and get the flag:
```python
import pickle
# open file for read
fdata = open('data', 'rb')
# deserialize data
unpickled = pickle.load(fdata, encoding="ASCII")
# convert integers to characters
chars = [chr(x) if str(x).isnumeric() else x for x in unpickled.values()]
flag = ''.join(chars)
print(flag)
```

![image](https://user-images.githubusercontent.com/38787278/93640528-671cad80-fa03-11ea-83fe-04c69e3828df.png)

Flag: DUCTF{p1ckl3_y0uR_m3554g3}

## <a name="addition"></a> Addition
Points: 425

#### Description
>Joe is aiming to become the next supreme coder by trying to make his code smaller and smaller. His most recent project is a simple calculator which he reckons is super secure because of the "filters" he has in place. However, he thinks that he knows more than everyone around him. Put Joe in his place and grab the flag.
>
>https://chal.duc.tf:30302/

### Solution
We are prompted with a page that seems to do calculations of whatever input we provide.

![image](https://user-images.githubusercontent.com/38787278/93662492-32dbd800-fa69-11ea-9b23-c928f3336576.png)

Let's try some other inputs to check what are our limitations. Entering `'A' * 10` we get `AAAAAAAAAA` so we are not limited to only numbers. I tried some more values and in the end I decided to try to obtain the source code. First step I entered `__file__` to get the file name: `./main.py `. Next, I read the file with `open(__file__, 'r').read()` and actually the source code contained the flag.

![image](https://user-images.githubusercontent.com/38787278/93662600-efce3480-fa69-11ea-85d9-13d8583b9d13.png)

Flag: DUCTF{3v4L_1s_D4ng3r0u5}

# <a name="forensics"></a> Forensics
## <a name="on-the-spectrum"></a> On the spectrum
Points: 100

#### Description
>My friend has been sending me lots of WAV files, I think he is trying to communicate with me, what is the message he sent?
>
>Author: scsc
>
>Attached files:
>
>   message_1.wav (sha256: 069dacbd6d6d5ed9c0228a6f94bbbec4086bcf70a4eb7a150f3be0e09862b5ed)

### Solution
We get a `.wav` file and, as the title suggest, we might find the flag in the spectogram. For viewing it I used [Sonic Visualizer](https://sonicvisualiser.org/). I played a little with the settings to view it better.

![image](https://user-images.githubusercontent.com/38787278/93643510-cc26d200-fa08-11ea-9337-6bfcd3bc6677.png)

Flag: DUCTF{m4bye_n0t_s0_h1dd3n}

# <a name="crypto"></a> Crypto
## <a name="rot-i"></a> rot-i
Points: 100

#### Description
ROT13 is boring!

Attached files:

    challenge.txt (sha256: ab443133665f34333aa712ab881b6d99b4b01bdbc8bb77d06ba032f8b1b6d62d)

### Solution
We recieve a file with the next content: `Ypw'zj zwufpp hwu txadjkcq dtbtyu kqkwxrbvu! Mbz cjzg kv IAJBO{ndldie_al_aqk_jjrnsxee}. Xzi utj gnn olkd qgq ftk ykaqe uei mbz ocrt qi ynlu, etrm mff'n wij bf wlny mjcj :).`
We know it's a form of ROT, but which one? Well, it's an incrementing one, starting from ROT-0 actually. I extracted only the encoded flag and I used the next script for deconding it:

```python
import string

flag_enc = "IAJBO{ndldie_al_aqk_jjrnsxee}"
flag_dec = []
k = 0

def make_rot_n(n, s):
    lc = string.ascii_lowercase
    uc = string.ascii_uppercase
    trans = str.maketrans(lc + uc, lc[n:] + lc[:n] + uc[n:] + uc[:n])
    return str.translate(s, trans)

for i in reversed(range(22 - len(flag_enc), 22)):
    flag_dec.append(make_rot_n(i, flag_enc[k]))
    k += 1

print(''.join(flag_dec))
```

Flag: DUCTF{crypto_is_fun_kjqlptzy}

# <a name="reversing"></a> Reversing
## <a name="formatting"></a> Formatting
Points: 100

#### Description
>Its really easy, I promise
>
>Files: formatting

### Solution
The file received is a 64 bits ELF binary.

![image](https://user-images.githubusercontent.com/38787278/93664106-1c3b7e00-fa75-11ea-9d5c-0b5d2a63dee0.png)

Running `strings` on it gives us some clues, but not the entire flag. I opened the bynary in [Radare2](https://github.com/radareorg/radare2) to better analyze it. I guess you can get the flag in simpler ways, but I'm trying to get better with this tool.

I opened it with `r2 -d formatting`, analyzed it with `aaa` and looked over the assembly.

![image](https://user-images.githubusercontent.com/38787278/93664244-01b5d480-fa76-11ea-9ccb-ef7373277bd2.png)

I saw multiple times characters are inserted in `var_90h` so I assumed that's the flag. I set a breakpoint on `lea rax, [var_90h]` and one one `mov byte [rbp + rax - 0x90], dl`. After the first breakpoint the `var_90h` contained only `DUCTF{`.

![image](https://user-images.githubusercontent.com/38787278/93664333-bf40c780-fa76-11ea-8d82-55cc2f9e36c3.png)

However, after the second breakpoint we get the flag.

![image](https://user-images.githubusercontent.com/38787278/93664376-0dee6180-fa77-11ea-9d9c-07c8c1f224b4.png)

Flag: DUCTF{d1d_You_Just_ltrace_296faa2990acbc36}
