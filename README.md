# PAN-OS GlobalProtect Portal Scanner

Determine the Palo Alto PAN-OS software version of a remote GlobalProtect portal or management interface.

Developed with ❤️ by the Bishop Fox [Continuous Attack Surface Testing (CAST)](https://www.bishopfox.com/continuous-attack-surface-testing/how-cast-works/) team.

- [Description](#description)
- [Getting Started](#getting-started)
- [Back Matter](#back-matter)

## Description

Palo Alto's GlobalProtect portal, a feature of PAN-OS, has been the subject of 
[several critical-severity vulnerabilities](https://security.paloaltonetworks.com/?severity=CRITICAL&product=PAN-OS&sort=-date) that can allow authorization bypass, unauthenticated remote code execution, etc. From an external perspective, it can be difficult to tell if you're running a patched version of PAN-OS since the GlobalProtect portal and management interface don't explicitly reveal their underlying software version.

To assist PAN-OS users in patching their firewalls, this scanner examines the `Last-Modified` and `ETag` HTTP response headers for several static web resources, and associates those values with specific PAN-OS releases. For example, note the `ETag` in the following HTTP response from the GlobalProtect portal login page:

```
$ curl -skI https://example.com/global-protect/login.esp
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
ETag: "6e185d5daf9a"
```

Examining the last 8 characters of the `ETag` gives us the hexadecimal epoch time `5d5daf9a`, represented as `1566420890` in decimal format. We can convert this epoch time to a human-readable format using the UNIX `date` utility:
```
$ date -d @1566420890
Wed 21 Aug 2019 08:54:50 PM UTC
```

Using the attached `version-table.txt`, we can determine that this instance of GlobalProtect portal is running on PAN-OS version `8.1.10`, and is therefore vulnerable to 
[CVE-2020-2034](https://security.paloaltonetworks.com/CVE-2020-2034), an OS command injection vulnerability in GlobalProtect portal, and should consequently be patched.

```
$ awk '/Aug.*21.*2019/ {print $1}' version-table.txt 
8.1.10
```

This scanner automates the process described above, suggesting an exact (or approximate) underlying PAN-OS version for a remote GlobalProtect portal or management interface.

## Getting started

### Install

```
$ git clone https://github.com/noperator/panos-scanner.git
```

### Usage

Note that this script requires `version-table.txt` in the same directory.
```
$ python3 panos-scanner.py -h
usage: Determine the software version of a remote PAN-OS target. Requires version-table.txt in the same directory.
       [-h] [-v] -t TARGET

optional arguments:
  -h, --help  show this help message and exit
  -v          verbose output
  -t TARGET   https://example.com
```

In the following example, `https://example.com/global-protect/portal/images/favicon.ico` has an HTTP response header that indicates that it's running PAN-OS version `8.0.10`.
```
$ python3 panos-scanner.py -t https://example.com
8.0.10 2018-05-04 (exact)
```

Also supports verbose output.
```
$ python3 panos-scanner.py -v -t https://example.com
[*] https://example.com
[+] 200 global-protect/login.esp
[*] 2018-05-03 ~ 2018-05-04 => 8.0.10
[+] 200 global-protect/portal/css/login.css
[*] 2018-05-03 ~ 2018-05-04 => 8.0.10
[*] 2018-05-04 => 8.0.10
[+] 200 global-protect/portal/images/favicon.ico
[*] 2018-05-04 => 8.0.10
[+] 200 global-protect/portal/images/logo-pan-48525a.svg
[*] 2018-05-04 => 8.0.10
[-] 404 login/images/favicon.ico
[-] 404 js/Pan.js
8.0.10 2018-05-04 (exact)
```

## Back matter

### Legal disclaimer

Usage of this tool for testing targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

### See also

- [Palo Alto Networks Security Advisories](https://security.paloaltonetworks.com/)

### To-do

- [ ] Stop after one exact match
- [x] Simplify output
- [x] Support verbose CLI option

### License

This project is licensed under the [MIT License](LICENSE.md).
