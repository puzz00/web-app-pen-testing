# Web Application Information Gathering

## Overview

This is the first step in a web app penetration test. We need to be thorough and methodical as we want to gather as much information about the target as possible. If we have a large attack surface, it is easier to successfuly compromise it. We need to let the client know about their entire web infrastructure, so we need to find it and know about it. There are two different kinds of information gathering - *passive* and *active*.

Passive information gathering is when we are not actively engaging with the target, such as when we browse the public website and note down names of employees.

Active information gathering is when we actively engage with the target, such as when we try zone transfers. We need to have authorisation before we begin active information gathering techniques.

During the information gathering phase of our penetration test, we need to record everything we discover so we can use it later on.

>[!IMPORTANT]
>There is no such thing as unncecessary information - we need to take notes and keep records of everything

We are looking for lots of different sorts of information, such as:

- Website and domain ownership
- IP addresses, domains and subdomains - DNS enumeration
- Hidden files and directories
- Hosting infrastructure (web server, CMS, Databases etc)
- Presence of defensive solutions such as web application firewalls

We can categorise the types of information we are looking for based on whether they can be found using passive or active methods:

- Passive Techniques
    - Identifying domain names and domain ownership
    - Discovering hidden and / or disallowed files and directories
    - Identifying web server IP addresses and DNS records
    - Identifying web technologies being used on target sites
    - WAF detection
    - Identifying subdomains
    - Identifying website content structure
- Active Techniques
    - Downloading and analysing website and / or web app source code
    - Port scanning and service discovery
    - Web server fingerprinting
    - Web app vulnerability scanning
    - DNS zone transfers
    - Subomain enumeration using brute-force techniques

We have lots of tests and checks to perform. To make sure that we cover everything we need to, and therefore to work with a sound methodology, we can use the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/v42/) which can act as a check-list for this initial phase of our web penetration test.

### OWASP Web Security Testing Guide

The [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/v42/) allows us to have a sound and thorough methodology to test websites and web applications. It offers advice on how to test for common vulnerabilities along with ways to remediate them.

Another useful tool which helps us keep track of what we have tested along with any findings we have made is a spreadsheet which is based on the OWASP Web Security Testing Guide. It has CWE details and is a great way to ensure that we are performing thorough web tests. A copy of this spreadsheet can be found [here](https://github.com/tanprathan/OWASP-Testing-Checklist/blob/master/OWASP_WSTG_Checklist.xlsx)

## Finding Ownership and IP Addresses

### Whois

Whois queries databases which contain information regarding who owns internet resources such as domain, ip addresses and ip address blocks. We can use it from the command line or via third party web-based tools.

Identifying basic information about domains is important as it is useful for the following tests which we perform. We can use whois to find out lots of useful information at the start of a web penetration test. We can feed it a domain name or an IP address.

A simple command to use from the command line is: `sudo whois targetsite.com` We do not need to specify the protocol as we are looking just at the domain.

If we see that an asset is coming up to the end of its registry expiry date and nobody has renewed it, it might suggest to us that the asset is not considered very valuable to its owner.

We can find nameservers for the domain. Nameservers translate domain names into IP addresses - they are a key part of DNS. We might get information about proxy servers here since some providers such as cloudflare proxy web server IP addresses so if we use a tool such as `host` to try to find the IP address of a domain we will instead be given the IP address of the cloudflare proxy server.

We can use IP addresses with whois like this: `sudo whois 104.21.44.108` This will let us know who owns the IP address and / or IP block which it belongs to. If the web servers IP address is being hidden by a proxy server, we will get information relating to the proxy server. It is useful to know IP ranges which belong to the target organisation since we can then test all of the other IP addresses in the block which they own.

We might find that the web server is not hiding behind a proxy server. We will get information about the target web server if this is the case. We can research the registrar and other information we find using whois.

We can use web services such as [domaintools](https://whois.domaintools.com) to perform whois lookups. The results can be easier to read.

### Netcraft

There is an online tool which can be found at [netcraft](https://www.netcraft.com/)

This tool can be used to *fingerprint* websites. It gives us a good high-level overview of we are up against when running web penetration tests. We therefore run it right at the start of our testing cycle along with `whois`

Netcraft returns lots of useful information. We can get to know more about technologies being used by the website - this means we get a basic fingerprint of the website just by using netcraft. We can also find out more about Content Management Solutions which might be running on the website from the tracking cookie information. Netcraft will also show us scripting frameworks such as javascript libraries which are being used.

### Passive DNS Enumeration

Once we have gained a high level overview of the website using `whois` and `netcraft` we can turn our attention to DNS enumeration. This allows us to build a more detailed map of the target site and its infrastructure.

We can use `dnsrecon` online or from the command line. A simple search can be started using: `sudo dnsrecon -d targetsite.com` The IP addresses returned are useful as they widen the attack surface.

Another good tool is [dnsdumpster](https://dnsdumpster.com/)

This tool also lets us see visible hosts from an attackers perspective. It shows us a map of what it discovers. We can export this map. We do not need to specify the protocol when we use dnsdumpster.

These passive techniques help us to start building our map of the target organistaions web presence. We can deepen this using active methods.

### Active DNS Enumeration

We can perform *active DNS enumeration* by interacting with the DNS nameserver for a domain.

We want to retrieve IP addresses for different machines on the domain along with subdomain information and mail servers.

We can use `dnsdumpster` to find out information about the DNS servers for a given domain. This is a passive technique which gives similar information to `sudo dnsrecon -d victimsite.com`

The `dnsenum` tool performs active techniques as well as passive ones. We can use: `sudo dnsenum victimsite.com` to get information about the specified domain. We can get similar information using: `sudo fierce -dns victimsite.com`

#### Zone Transfers

Administrators sometimes want to transfer the DNS records from one nameserver to another as a backup. This process is known as a *zone transfer*. If this has not been properly configured, we can also get a copy of the DNS records using a command such as: `sudo dig -t AXFR @ns1.victimsite.com victimsite.com +nocookie` 

>[!TIP]
>We can change the *nameserver* to query by using the `@` symbol as it lets us specify the *nameserver* we want to use

This provides useful information such as internal network addresses along with a good overview of the target organisations network. We can find subdomains and internal subdomains as well.

We can enumerate the *reverse* dns zone with `dig` using this command: `sudo dig -t AXFR @10.10.10.8 -x 192.168` In this example we are assuming that the target organisation uses the ip address block `192.168.x.y` so we specify that we want to check ip addresses in that block.

### Further DNS Enumeration

We can use `nmap` to search for DNS servers as port 53 on UDP and sometimes TCP will be open on them

To enumerate UDP we can use:

```bash
sudo nmap -T4 -Pn -n -p53 --open -sUV --version-intensity 0 -oG udp_dns.gnmap 10.10.10.0/24
```

For TCP we can use:

```bash
sudo nmap -T4 -Pn -n -p53 --open -sS -oG tcp_dns.gnmap
```

We can combine the results of these scans using:

```bash
sudo grep "53/open/" *.gnmap | awk '{print $2}' | sort | uniq > dns_targets.txt
```

>[!TIP]
>If the above commands do not return any results, we can try them again but with the `--source-port=53` option set as sometimes DNS servers will only accept incoming traffic from port 53

Once we have found DNS servers for a domain, we can enumerate them to find out more using `dig` Here are some commands which are useful:

```bash
sudo dig @10.10.10.8 target.com ns +noall +answer +nocookie
```

```bash
sudo dig @10.10.10.8 target.com mx +noall +answer +nocookie
```

We can use `dig` to enumerate further by using it on new subdomains or servers which we find:

```bash
sudo dig @10.10.10.8 mail.target.com +noall +answer +nocookie

sudo dig @10.10.10.8 ns1.target.com +noall +answer +nocookie
```

We can bruteforce subdomains via DNS using the `host` tool combined with a wordlist. Here is a bash script which does so:

```bash
sudo for name in $(cat /usr/share/dnsrecon/subdomains-top1mil-20000.txt); do host $name.victimsite.com 10.10.10.8 -W 2; done | grep 'has address'
```

We can enumerate DNS using *reverse* lookups whereby we look for a PTR record which maps an IP address to a domain name. We can do this with: `sudo dig @10.10.10.8 -x 10.10.10.158 +nocookie`

>[!NOTE]
>The `-x` flag specifies that we want to run a *reverse* lookup

We can bruteforce the *reverse* DNS zone using a bash script such as the one below:

```bash
sudo for ip in $(cat targets.txt); do dig @10.10.10.8 -x $ip +nocookie; done | grep 'victimsite.com' | grep PTR
```

We will need to generate a list of possible IP addresses for the above command to work - here we have saved them as `targets.txt`

## Web Server Metafiles

### robots.txt

Most wesites and apps have a `robots.txt` file which specifies which directories the developers do not want web crawlers to index. These disallowed entries can leak information to us regarding interesting directories and also the structure and functionality of the website or app. This file can usually be accessed by appending `/robots.txt` to a url.

### Sitemap

Another useful file is the sitemap. This is usually referenced in `robots.txt` so crawlers know which directories to index. We can access it and use it to better understand the layout of the target site.

## Google Dorks

Google dorks are advanced web searches which use search operators. We can use them to enumerate lots of useful and specific information about target websites. This is a *passive* technique.

We can use `site:tesla.com` to limit the results to `tesla.com` and its subdomains. We can combine these advanced search terms with regular search terms like so: `employees site:tesla.com`

We could make the search more specific using `inurl:admin` These search terms can be combined like so: `site:tesla.com inurl:admin` Another search operator we can use which is similar to `inurl` is `intitle:admin`

We can use *wildcards* to look for specific resources such as subdomains: `site:*.tesla.com`

We can limit results to pages which have specific types of file using `filetype:pdf`

We can search for directory listing using: `intitle:"index of"`

If we want to see what a website used to look like, we can use `cache:tesla.com` We can also have a look at the [wayback machine](https://archive.org/web) which keeps copies of websites from different points in the past.

There is a very good resource to find useful advanced search terms at [exploit-db](https://www.exploit-db.com/google-hacking-database) We can search it for terms such as `wp` to help us tailor our attacks to infrastructure which the target organisation is using.

The following commands search for information leakage in the form of passwords: `inurl:auth_user_file.txt` or `inurl:passwd.txt` or `intitle:"index of" "credentials"` We can use `inurl:wp-config.bak` to search for information leakage in back up files of the wordpress configuration file.

We can use google dorks to really focus our attacks. Here is an example which searches for government websites which have exposed CSV files via directory listing being enabled: `site:gov.* intitle:"index of" *.csv`

## Web App Fingerprinting

We want to find out as much as we can about the target web apps. We can use tools to fingerprint the technology which is being used on them. This is useful as we can then search for vulnerabilities which potentially affect those technologies which are being used by the target apps.

We can use mozilla extensions such as `builtwith` and `wappalyzer` These give us a good overview of the technologies which are being used by the target apps. We can also use a command line tool called `whatweb` We can run this tool using: `sudo whatweb targetsite.com`

### Web Application Firewall Detection

Web Application Firewalls are used by most websites and apps. They protect the IP address of the web server as well as offering other services. Each WAF is slightly different and it is therefore important to identify which WAF is being used by the target website or app.

One tool we can use is `wafw00f` - this can be used like so: `sudo wafw00f https://targetsite.com` This tool will attempt to identify if a WAF is being used and if so then which WAF it is. We can use the `-a` flag to run more checks: `sudo wafw00f -a https://targetsite.com`

>[!TIP]
>If there is no WAF being used, it may well be that the IP address which we find for the web server is not being proxied

## Source Code Analysis

### HTTrack

It is useful to have a local version of a website so we can analyse the source code thoroughly looking for potential injection vulnerabilities, hidden comments and so on.

We can run a wizard for `httrack` by just entering `httrack` in the command line. We can then specify a website such as `https://targetsite.com` and then modify the download by answering the questions which the wizard asks.

We will have a local copy of the website and its various resources once `httrack` has finished downloading everything. We can then enumerate the website to understand more about its structure. We can also have a look at javascript being used in order to find parameters to test for XSS vulnerabilities.

>[!TIP]
>Enumerating front-end javascript can yield useful data

### Eyewitness

Eyewitness screenshots websites and / or applications which are running. It provides us with a useful html report. We can use the results to help us know more about the web presence of the target organisation. Eyewitness also lets us download javascript being used by the web apps. It can also identify default credentials if they are known.

We need to create a txt file which contains the domains or IP addresses of the sites which we want eyewitness to target. Each domain needs to be on a new line. We can then run eyewitness using: `eyewitness --web -f domains.txt -d target_site` This tool lets us quickly see what is running on the various websites and / or apps which we are interested in finding out more about.

>[!NOTE]
>I have found eyewitness to exit with status code 1 and not work if I try to run it using `sudo` privileges

## Crawling and Spidering

### Crawling

Crawling a website means we manually move around a website via a proxy such as burpsuite so we can create a map of the site. We submit data to forms and click on all the links which we can find. We are trying to understand how the website or app is laid out and how it works - its functionality. This is considered a passive method as we are only navigating what is publicly availabe.

We can do this manually without a proxy server, but doing it through a proxy is much better as it keeps track of everything we access and it builds a user friendly sitemap which will help us better understand the website or app.

When we use burpsuite, it is best to add the target domains and or IP addresses to our scope and only log items which are in scope. We need to switch off the intercept tool before we begin clicking on the links and submitting data.

### Spidering

This is when we use an automated tool to navigate the website. It is considered an active method as the spider will attempt to find and access resources which are not publicly available as well as those which are. The spider follows links recursively and is quite noisy. Spidering will tend to find more resources than crawling.

We can use OWASP Zap to spider a target site. We can change the mode - it is best to use the *safe* or *standard* modes. We can navigate to the target site and then we can go to the spider tool inside the tools dropdown menu. We can then select the website or app which we want to spider. We will want to enable the *recurse* option. The *advance* options let us configure the *depth* of the spidering and the *speed* we want the spider to work.

Once the spidering has started, we will see links. Those marked *red* are links to external sites whilst those in *green* are within the context of the target site. Once the scan has finished, we can export the results as a CSV file. We can right click on resources which have been found and then open them in a browser.

## Enumerating Web Servers

We want to find out more about the technologies which are being used by the web server along with which server we are dealing with for example *Apache2* or *IIS* We also want to know which *version* of the web server is being used. We want to try to work out what type of stack is being used. An example would be if *wordpress* is being used with *apache* then it stands a good chance that there is a *mysql* server also as it suggests that a LAMP stack is being used.

>[!IMPORTANT]
>The main points here are *which web server software* is being used and *which version* is it

We can use *nmap* to scan the web server in order to enumerate the technology and version being used. This is an active technique and can be done simply with `sudo nmap -Pn -n -sV -F 10.10.10.22` The `http-enum` script is useful when fingerprinting web servers: `sudo nmap -Pn -n -sV -p80 --script=http-enum 10.10.10.22`

Once we have discovered the web server and version which is being used, we can use a tool such as `searchsploit` to look for vulnerabilities and exploits. We can also use search engines to research the technology being used.

>[!IMPORTANT]
>We need to scan the *entire* TCP port range as services can be running on unexpected ports

We can use *msfconsole* to fingerpring web servers with: `use auxiliary/scanner/http/http_version`

We can also find out about the web server using passive techniques such as information leakage in places like default pages or directory listing. Another passive technique is *banner grabbing*. The server response header lets us know which web server and version is being used. We can find this via a web proxy but it is often disabled.

In order to look for directories which might leak information, we can use `gobuster` to do some *directory busting* along with a wordlist such as the one at `/usr/share/metasploit-framework/data/wordlists/directory.txt`

## Subdomain Enumeration

We can use passive and active methods to find subdomains for target organisations and domains. The passive methods include using advanced searches aka Google dorks.

Sublist3r is a tool which lets us use passive techniques - it searches for subdomains via a number of search engines - as well as active bruteforcing via `subbrute` which is built into it. The basic command is `sudo sublist3r -d targetsite.com`

We can use `fierce` to bruteforce subdomains. A command we can use is `sudo fierce --domain targetsite.com --subdomain-file /opt/Seclists/Discovery/fierce-hostlists.txt` This tool gives us IP addresses for the subdomains if it can retrieve them. We can then scan the IP addresses using `nmap` to look for services.

### wfuzz

Another good tool is `wfuzz` - we can first of all run it to find numbers of words or lines which show up in unwanted results: `sudo wfuzz -u http://devvortex.htb -H "Host: FUZZ.devvortex.htb" -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt`

We can then hide the number of words or lines which show up in unwanted results: `sudo wfuzz --hl 7 -u http://devvortex.htb -H "Host: FUZZ.devvortex.htb" -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt`

### gobuster

Whilst looking at enumerating subdomains, it might be worth noting that we can look for *virtual hosts* using: `sudo gobuster vhost -u http://wekor.thm -w /usr/share/amass/wordlists/subdomains-top1mil-20000.txt`

## Vulnerability Scanning Web Servers

We can use a tool called `Nikto` to speed up - automate - fingerprinting and vulnerability scanning websites and web applications. The tool is user friendly, but if we need detailed help regarding it we can use the command `nikto -Help`

A basic scan can be launched against a target site using: `sudo nikto -h http://10.10.10.15` This scan will return useful information in the terminal window. It is easier to work with the results in an html report - we can get `Nikto` to generate this for us using: `sudo nikto -h http://10.10.10.15 -o results.html -Format htm`

Once we have generated a report using `Nikto` we can manually explore each issue which it has identified. 

>[!NOTE]
>Nikto is a great tool to use against a website or web application but it needs to be combined with manual enumeration techniques

## Enumerating Files and Directories

Hidden files and directories can yield useful information. There are different tools which allow us to find these resources. Whichever one we choose to use, it is important that we *specify a good wordlist*. We can try more than one wordlist, and we can scan for hidden directories and files inside new directories which are discovered. The `common.txt` wordlist which can be found at `/usr/share/wordlists/dirb/common.txt` is a good one for general directory busting, but `SecLists` has more thorough ones.

For web app testing, we can try using wordlists found at `/opt/SecLists/Discovery/Web-Content` A good one is the `directory-list-lowercase-2.3-medium.txt` This can be used if we have ascertained that lower or upper case characters are not important so we can use the lowercase wordlist to save time.

### Gobuster

Gobuster is fast as it is written in the go language. We can use it to find directories, subdomains via DNS enumeration and virtual hosts. A simple directory scan can be launched using: `sudo gobuster dir -u http://192.168.56.101 -w /usr/share/wordlists/dirb/common.txt`

We can specify file extensions to look for files of the specified types using the `-x` flag like so: `sudo gobuster dir -u http://192.168.56.101 -w /usr/share/wordlists/dirb/common.txt -x old,bak,sh,php,txt`

We can get Gobuster to follow `302` redirects using the `-r` flag: `sudo gobuster dir -u http://192.168.56.101 -w /usr/share/wordlists/dirb/common.txt -x old,bak,sh,php,txt,xml -r`

We can filter out specific return status codes using the `-b` flag like so: `sudo gobuster dir -u http://192.168.56.101 -w /opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2 -b 403,404 -x php,xml -r`

A good general purpose wordlist to use is `/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt`

We can also enumerate *virtual hosts* using: `sudo gobuster vhost -u http://192.168.56.101 -w /usr/share/amass/wordlists/bitquark_subdomains_top100k.txt`

## Automated Recon

### Amass

We can use the OWASP tool called `amass` to automate website mapping along with enumeration and both passive and active information gathering. The basic usage of the tool needs us to specify a *subcommand* along with options for it.

An example of using the `enum` subcommand is: `sudo amass enum -d targetsite.com` We can specify passive only techniques with the `-passive` flag like so: `sudo amass enum -passive -d targetsite.com`

We can save the results of our scans into a specified directory using the `-dir` flag. We can also see the sources for where `amass` found subdomains using the `-src` flag. We can also get the IP addresses of the subdomains using the `-ip` flag. These commands can be combined into one like so: `sudo amass enum -d targetsite.com -src -ip -dir ./amass_results` We can explicitly specify that we want `amass` to brute-force subdomains by adding the `-brute` flag to our command: `sudo amass enum -d targetsite.com -src -ip -brute -dir ./amass_results`

We can get `amass` to generate different types of report. One kind is `d3` which will show us in an html file a graphic visualisation of what has been discovered. We need to use the `viz` subcommand like so: `sudo amass viz -dir ./amass_results -d3` The `-dir` flag in this case is used to specify the directory where the results are for the scan which we want to generate a report for. It makes sense, therefore, to always create a new directory for each new `amass` scan which we perform.

>[!TIP]
>Knowing how to enumerate web apps manually as well as with automated scripts is important as manual enumeration can really help us understand our targets and better fine-tune our attacks

---
>if you know the enemy and know yourself, your victory will not stand in doubt