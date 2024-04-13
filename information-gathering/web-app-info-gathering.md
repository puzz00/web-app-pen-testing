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