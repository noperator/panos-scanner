# PAN-OS GlobalProtect Portal Scanner

Determine the Palo Alto PAN-OS software version of a remote GlobalProtect portal or management interface.

Developed with ❤️ by the [Bishop Fox Cosmos](https://bishopfox.com/platform) (formerly CAST) team.

- [Description](#description)
- [Getting started](#getting-started)
- [Back matter](#back-matter)

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

This scanner automates the process described above, suggesting an exact (or approximate) underlying PAN-OS version for a remote GlobalProtect portal or management interface. When multiple versions are associated with a given date, this tool will display all version matches as a comma-separated list; e.g, `7.1.24-h1,8.0.19-h1,8.1.9-h4` for `2019-08-15`.

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
       [-h] [-v] [-s] [-c] -t TARGET

optional arguments:
  -h, --help  show this help message and exit
  -v          verbose output
  -s          stop after one exact match
  -t TARGET   https://example.com
```

In the following example, `https://example.com/global-protect/portal/images/favicon.ico` has an HTTP response header that indicates that it's running PAN-OS version `8.0.10`.

```
$ python3 panos-scanner.py -s -t https://example.com | jq '.match'
{
  "date": "2018-05-04",
  "versions": [
    "8.0.10"
  ],
  "precision": "exact",
  "resource": "global-protect/portal/images/favicon.ico"
}
```

<!--

Also supports verbose output.

```
$ python3 panos-scanner.py -v -t https://example.com
[*] https://example.com
[+] global-protect/login.esp
[*] 2018-05-03 ~ 2018-05-04 => 8.0.10
[-] php/login.php (ReadTimeout)
[+] global-protect/portal/css/login.css
[*] 2018-05-03 ~ 2018-05-04 => 8.0.10
[*] 2018-05-04 => 8.0.10
[-] js/Pan.js (HTTPError)
[+] global-protect/portal/images/favicon.ico
[*] 2018-05-04 => 8.0.10
[-] login/images/favicon.ico (HTTPError)
[+] global-protect/portal/images/logo-pan-48525a.svg
[*] 2018-05-04 => 8.0.10
8.0.10 2018-05-04 (exact)
```

This tool doesn't currently support reading from a list of targets. Instead, here's a useful way to test multiple targets using a Bash `for` loop, along with the `tr` and `column` utilities. You can equivalently use a Bash `while` loop over the contents of a text file: `$ cat target_list.txt | while read TARGET; do ...`.

```
$ for TARGET in \
https://example.com \
https://nomatchexample.com \
https://doublematchexample.com \
http://nonexistentexample.com \
; do
    echo -n "$TARGET;"
    python3 panos-scanner.py -s -t "$TARGET" | tr '\n' ';'
    echo
done | column -t -s ';'

https://example.com             8.1.9 2019-07-03 (exact)
https://nomatchexample.com      no matches found
https://doublematchexample.com  8.1.12 2019-12-10 (exact)  9.1.0 2019-12-11 (approximate)
http://nonexistentexample.com   ConnectionError
```

-->

## Back matter

### Legal disclaimer

Usage of this tool for testing targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

### Acknowledgements

Thanks [@k4nfr3](https://github.com/k4nfr3) for providing updates to the version table, and for building in the option to print a URL for Palo Alto's security advisories page.

### See also

- [Shodan Facet Analysis — PAN-OS Version](https://beta.shodan.io/search/facet?query=http.html%3A%22Global+Protect%22&facet=os)
- [A Look at PAN-OS Versions with a Bit of R](https://rud.is/b/2020/07/10/a-look-at-pan-os-versions-with-a-bit-of-r/)
- [Palo Alto Networks Security Advisories](https://security.paloaltonetworks.com/)

### To-do

- [x] Stop after one exact match
- [x] Simplify output
- [x] Support verbose CLI option
- [x] Perhaps output JSON instead, to be processed with `jq`

### License

This project is licensed under the [MIT License](LICENSE.md).
