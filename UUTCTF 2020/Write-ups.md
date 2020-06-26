The CTF had a bad infrastructure with a lot of down time. I managed to download a few challenges at once and solved what I could.

Table of contents
- [Web](#web)
  - [Let me in](#let-me-in)
- [Forensics](#forensics)
  - [White Noise](#white-noise)
- [Misc](#misc)
  - [Noisy Wind](#noisy-wind)
- [Crypto](#crypto)
  - [Mess Up - Warm Up](#mess-up)

# <a name="web"></a>Web
## <a name="let-me-in"></a> Let me in
Points: 50
#### Description
>Go inside the website and it will show you the flag.
>
>URL: http://185.206.93.66:800/
### Solution
If we acces the given site we are asked to log in in order to get the flag.

![web-let-me-in](https://user-images.githubusercontent.com/38787278/85196121-a0e4f780-b2e0-11ea-9ecd-20b0cf2a23f4.png)


I tried some SQL Injection, but it didn't work so I decided to go to Burp to find more.
I saw that the response from the `GET /` request contains the credentials.

![web-let-me-in-2](https://user-images.githubusercontent.com/38787278/85196133-b0644080-b2e0-11ea-9b4f-2284497154cd.png)

After insertting the credentials we received a file called `auth` with the flag.

![web-let-me-in-3](https://user-images.githubusercontent.com/38787278/85196141-ba863f00-b2e0-11ea-82ad-db8598940dba.png)

Flag: UUTCTF{I_J45T_H4T3_C0R0NA}

# <a name="forensics"></a> Forensics
## <a name="white-noise"></a> White Noise
Points: 100
#### Description
>The flag is inside the attached file.Extract it:
>
>Hint: "uUt_CtF_2020" leads you to the flag.

### Solution
We are given a file called `WhiteNoise.bin`.
Time to get some information. I ran `file`, `foremost`, `binwalk` and `strings`. `file` command couldn't identity what type of file it is, but `strings` reveals that the file was encrypted with `aescrypt`.

![image](https://user-images.githubusercontent.com/38787278/85202025-46619080-b30c-11ea-9ec4-ca3796d3f7aa.png)

I installed [aescrypt](https://www.aescrypt.com/download/) and tried to decrypt the file using rockyou dictionary. I didn't succeed, so I read again the description. I tried as password `uUt_CtF_2020` and it worked.

![image](https://user-images.githubusercontent.com/38787278/85202202-5fb70c80-b30d-11ea-87e2-4da0cad75217.png)

The obtained file is an audio file. Listening to it it seems to be played backwards. I used this site to reverse the audio file: [Online Audio Reverser](https://audiotrimmer.com/de/online-audio-reverser/)
Listening the reversed audio we hear the next thing:
>Congratiolations you found the uutctf flag. The flag is we are anonymous.

Flag: UUTCTF{we are anonymous}

# <a name="misc"></a> Misc
## <a name="noisy-wind"></a> Noisy Wind
Points: 100
#### Description
> Can you hear the flag?

### Solution
We are given a `.wav` file. We open it in Sonic Visualiser. Nothing at first, but after the add a spectogram layer we start to see some text. I played a little with the settings from the right pannel so that the text will be more visible.

![image](https://user-images.githubusercontent.com/38787278/85204256-e246c880-b31b-11ea-8a69-c43b7440cb56.png)

Flag: UUTCTF{StEg0_1s_sUch_4_fUn}

# <a name="crypto"></a> Crypto
## <a name="mess-up"></a> Mess Up - Warm Up
Points: 25
#### Description
>A little messy message!!!

### Solution
We are given a text file that contains:
>VVVUQ1RGey4tLS0tIC0uIC0gLi4uLS0gLi0uIC4gLi4uLi4gLSAuLi4tLSAtLi4gLS4uLi4tIC4uIC0uIC0uLi4uLSAtLSAtLS0tLSAuLS4gLi4uLi4gLiAtLi4uLi0gLS4tLiAtLS0tLSAtLi4gLi4uLS19

This seems to be a base64 encoded string, so we'll go to [CyberChef](https://gchq.github.io/CyberChef/) to decode it.

![image](https://user-images.githubusercontent.com/38787278/85197571-83b52680-b2ea-11ea-82c5-5f723431dd69.png)

The output needs further decoding, this time from Morse Code.

![image](https://user-images.githubusercontent.com/38787278/85197610-de4e8280-b2ea-11ea-83e9-ab9b9193febf.png)

Flag: UUTCTF{1NT3RE5T3D-IN-M0R5E-C0D3}
