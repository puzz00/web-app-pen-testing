# Deobfuscation

Deobfuscation is an important skill to learn as we often encounter code - especially javascript - which has been obfuscated. This is done to hide malicious code from humans and automated intrustion detection and prevention systems.

## Finding Javascript

When we are testing web apps it is important to always review the javascript code.

We find this on the frontend - we can look at the page source code in a browser or a proxy server such as burpsuite.

Javascript will usually be kept in an external resource which is referenced inside the main source code of the web page.

When we look at the javascript we may well find it has been *obfuscated* so we need to learn how to *deobfuscate* it so we can understand what it does on the app.

![js1](/images/1.png)

![js2](/images/2.png)

![js3](/images/3.png)

![js4](/images/4.png)

![js5](/images/5.png)

## Code Obfuscation

In order to understand how to *deobfuscate* code we need to first of all understand how to *obfuscate* code.

Obfuscation is simply the process of making code difficult for humans to read whilst at the same time leaving it able to operate as intended.

>[!NOTE]
>Code tends to run slower when it has been obfuscated

Javascript operates on the client side and therefore the scripts can be easily found in source code. Languages like php and python which run on the backend of a web application do not need to be obfuscated as they are not accessible by a user. Since javascript is accessible it is commonly obfuscated.

Developers may well do this to make it more difficult for people to steal and reuse their code, but the most common use of obfuscation is by threat actors to hide the real intention of their code. This might be for example to download a trojan horse or other payload.

Obfuscation of code is usually achieved via the use of tools which take the source code and rewrite it though more advanced threat actors will obfuscate their code manually to make it more difficult to obfuscate it.

### Basic Obfuscation

There are simple ways to make javascript more difficult to read.

#### Minifying Javascript

We can *minify* different programing languages including javascript. The idea is to take long pieces of code and then put them onto one line which makes it more difficult to understand what the code does.

>[!NOTE]
>Minification is usually applied to large pieces of code as it doesnt look much different if there is not much code in the first place

There is an online tool called [javascript-minifier](https://www.toptal.com/developers/javascript-minifier) which will do this for us.

>[!NOTE]
>We tend to use the file extension `.min.js` when we have *minified* javascript code

#### Packing

We can *pack* javascript code using an online tool such as [BeautifyTools](https://beautifytools.com/javascript-obfuscator.php#)

This will make the code much harder to read.

![js6](/images/6.png)

The packed code still retains the original functionality.

![js7](/images/7.png)

Packers use a `(p,a,c,k,e,d)` function to rebuild code during execution. This function which accepts six arguments is a hallmark of packers. There are different packers and they each work slightly differently in that the `(p,a,c,k,e,d)` function can be different.

### More Advanced Obfuscation

The above methods do obfuscate code, but they tend to leave some strings in clear text which means that the functionality of the code might still be able to be worked out.

The [obfuscator.io](https://obfuscator.io/) tool does a good job.

We can change the `String Array Encoding` to `Base64` before we paste our javascript code into the tool and then click the `Obfuscate` button.

![js8](/images/8.png)

![js9](/images/9.png)

![js10](/images/10.png)

![js11](/images/11.png)

>[!TIP]
>We can combine techniques - the code can be *minified* then *packed* and then pasted into a tool such as is found at [obfuscator.io](https://obfuscator.io/)

![js12](/images/12.png)

![js13](/images/13.png)

## Code Deobfuscation

Now that we have an understanding of how we can *obfuscate* javascript we can start to learn how to *deobfuscate* it.

### Beautify the Code

To more easily read code which has been *minified* we can *beautify* the code.

We can do this using the *dev tools* of a web browser.

![js14](/images/14.png)

![js15](/images/15.png)

We can also use online tools such as [prettier](https://prettier.io/playground/)

![js16](/images/16.png)

We see that the code has been *packed* so we now need to *unpack* it.

### Unpacking Packed Javascript

We can use an online tool such as [unpacker](https://matthewfl.com/unPacker.html) to unpack packed javascript.

![js17](/images/17.png)

We can also find the `return` keyword at the end of the packed code and simply `console.log()` the value which is returned.

![js18](/images/18.png)

In this example we use `console.log(p);` to replace `return p;`

The output is *minified* so we just make it prettier as before.

![js19](/images/19.png)

![js20](/images/20.png)

### Analyzing the Code

>[!TIP]
>Getting to know at least the basics of javascript is very useful - we encounter lots of js code when conducting web app penetration tests - a repo on learning javascript is on the todo list...

We can start to analyze the code once we have deobfuscated it - it might be harmless - or it might be up to no good.

The code we have deobfuscated in this example contains one *function* called `generateSerial`

Lets have a look at it.

```javascript=
function generateSerial() {
    var flag = "HTB<REDACTED>";
    var xhr = new XMLHttpRequest();
    var url = "/serial.php";
    xhr.open("POST", url, true);
    xhr.send(null);
}
```

The first line of the function just declares a variable called `flag` and assigns the [htb](https://www.hackthebox.com/) flag to it - not a part of the core functionality of this function but necessary if we are completing the htb room hence we have redacted it :smiley:

The second line of the function which is `var xhr = new XMLHttpRequest()` instantiates a new `XMLHttpRequest` object.

This object is assigned to a variable called `xhr` and it lets us work with web requests by sending data to and receiving data from a web server. More info about it can be found at [www3schools](https://www.w3schools.com/js/js_ajax_http.asp)

The next line `var url = "/serial.php"` places the location of a .php resource into a variable called `url` - this will no doubt be used by the `XMLHttpRequest` object.

The final two lines of the `generateSerial` function just send a `POST` request to the `/serial.php` resource - no data is actually sent - we can see this in the line `xhr.send(null)` - the `null` datatype is sent rather than a *string* of data.

This function appears to do nothing - but we can test to see if the backend `/serial.php` script does anything once it receives a `POST` request - it might be that we can discover unreleased functionality which could be of interest to us.

### Testing the Functionality

We can use `curl` from our linux command line to test the functionality of the deobfuscated javascript function.

To introduce `curl` we can look at how we can make a `GET` request using it.

>[!NOTE]
>We can use the `-s` flag to *silence* data in the response which we dont need to see

```bash
sudo curl -s http://<SERVER IP:PORT>
```

![js21](/images/21.png)

Here we want to send a `POST` request so we specify this using the `-X` flag of `curl`

>[!NOTE]
>Since we have not specified any data to send in the `POST` body this is just an empty request

```bash
sudo curl -s http://<SERVER IP:PORT>/serial.php -X POST
```

We get some data returned - interesting...

![js22](/images/22.png)

#### Decoding Encoded Data

Whilst *encoding* data is not meant as a way to obfuscate - we do find *encoded* data and it is useful to be able to recognise common forms of *encoding* and know how to *decode* them.

>[!IMPORTANT]
>Never use *encoding* to try to hide sensitive data - *encoding* is designed to be easily *decoded* - it is different to *encryption* which is designed to only be *decrypted* by those authorized to do so

We tend to use *encoding* when sending data across networks as it makes it more reliable to send.

Two common forms of *encoding* are *base64* and *hex*

##### Base64

Base64 encoded data is easy to recognise as it only uses alpha-numeric characters along with `+` | `/` and `=`

This use of alpha-numeric characters reduces the number of special characters and helps the data transfer across networks more reliably.

Base64 encoded data often - though not always - ends with `=` characters as these are used to *pack* it. Packing is necessary if the length of the data is not a multiple of four.

To experiment with this we can encode strings in our command line using `echo "hello world" | base64`

We can *decode* data which has been *encoded* using *base64* easily in our command line by using `echo "bm90aGluZyB0byBzZWUgaGVyZQo=" | base64 -d`

>[!TIP]
>If we think the data is *base64* encoded but it does not end with `=` we can count the characters in it using `printf "bm90aGluZyB0byBzZWUgaGVyZSEK" | wc -m` - we expect the result to be a multiple of four

>[!NOTE]
>If we use `echo` instead of `printf` we will get one character extra since `echo` adds a *newline* character at the end

Coming back to our example we decode the data we recieved back from `/serial.php` and get a cleartext string.

We now send this cleartext string as a value to a parameter called `serial` which htb gave us. This is an opportunity to see how we can include data in the body of our `POST` request when using `curl` - we use the `-d` flag.

```bash
sudo curl -s http://<SERVER IP:PORT>/serial.php -d "serial=<REDACTED>" -X POST
```

We now receive a flag.

![js23](/images/23.png)

##### Hex Encoding

Hex encoding is another common way to encode data.

It encodes data as *hexadecimal* values which range from 0 to F

>[!TIP]
>Hexadecimal is just *base16* - we go from 0 to 9 and then use letters so A is decimal 10 | B is decimal 11 and so on until we reach F which is decimal 15

This use of hexadecimal values makes hex encoding easy to spot.

We can play about encoding data using hex in our command line using `echo "hello" | xxd -p`

If we want to decode hex encoded data we can use `echo "646f6e742075736520656e636f64696e6720746f20686964652073656e7369746976652064617461202d20656e637279707420696e73746561640a" | xxd -p -r`

##### Rot13

This is just an implementation of the rather old Caesar Cypher - yes named after Julius Caesar who supposedly used it in his military campaigns - a bit odd since most of his enemies wouldnt have been able to read latin anyway.

The Caesar Cypher is a simple shift cypher where we move along the alphabet one way to encrypt and then the same number the other way to decrypt - rot13 unsurprisingly uses a shift of 13

It is easy to recognise if rot13 - or the caesar cypher with any shift number - has been used because letters always map to the same letters so we can detect common patterns such as double letters or endings of - english - words such as ing | er | ed etc

We can implement our own bash tool to encrypt strings with rot13.

```bash
echo "hello" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

We can use the same to decrypt rot13.

```bash
echo "uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

##### Other Encodings

If we find different encodings being used our best bet is to research them online and look for online tools to decode them.

One useful tool which helps us identify which encoding has been used is [cipher identifier](https://www.boxentriq.com/code-breaking/cipher-identifier)

## Walkthrough Skills Test

As a final look at what has been covered in these notes we can walkthrough the final skills test found on htb

We first of all navigate to the web app of interest.

![js25](/images/25.png)

We will look at the source code and enumerate any frontend javascript we can find - this is always recommended when conducting a web app penetration test or working on ctf boxes.

![js26](/images/26.png)

![js27](/images/27.png)

The code has been obfuscated - now is the time to practice what we have been learning.

We will start by making the code prettier.

![js28](/images/28.png)

We then unpack the code.

![js29](/images/29.png)

The returned javascript has been minified so we use an online tool to make it easier to read.

![js30](/images/30.png)

Next we clean up the code and analyze what it is doing.

![js31](/images/31.png)

We use `curl` to test the `/keys.php` backend resource and by using the string which is sent to us in the server response we are able to obtain the final flag :smiley:

![js32](/images/32.png)

## Conclusion

These notes have gone over how we can obfuscate and deobfuscate javascript code in several simple ways.

It is important to analyze javascript code we find on web apps we are testing - hopefully we will be able to now handle code which has been obfuscated in the ways we have covered :smiley: