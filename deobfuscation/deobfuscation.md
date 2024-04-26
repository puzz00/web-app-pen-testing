# Deobfuscation

Deobfuscation is an important skill to learn as we often encounter code - especially javascript - which has been obfuscated. This is done to hide malicious code from humans and automated intrustion detection and prevention systems.

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

We can *minify* different programing languages including javascript. The idea is to take long pieces of code and then put them onto one line which makes it more difficult to understand what the code does. There is an online tool called [javascript-minifier](https://www.toptal.com/developers/javascript-minifier) which will do this for us.

>[!NOTE]
>We tend to use the file extension `.min.js` when we have *minified* javascript code

#### Packing

We can *pack* javascript code using an online tool such as [BeautifyTools](https://beautifytools.com/javascript-obfuscator.php#)

This will make the code much harder to read.

Packers use a `(p,a,c,k,e,d)` function to rebuild code during execution. This function which accepts six arguments is a hallmark of packers. There are different packers and they each work slightly differently in that the `(p,a,c,k,e,d)` function can be different.

### More Advanced Obfuscation

The above methods do obfuscate code, but they tend to leave some strings in clear text which means that the functionality of the code might still be able to be worked out.

The [obfuscator.io](https://obfuscator.io/) tool does a good job.

We can change the `String Array Encoding` to `Base64` before we paste our javascript code into the tool and then click the `Obfuscate` button.

