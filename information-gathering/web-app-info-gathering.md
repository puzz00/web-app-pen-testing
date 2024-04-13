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

