# ELEGANTBOUNCER
![alt text](logo.png) 

Just some playground experimental tool for detection of the FORCEDENTRY (CVE-2021-30860) exploit inside PDF files.

## Getting started
```
elegant-bouncer v0.1
ELEGANTBOUNCER JBIG2/PDF scanner for FORCEDENTRY (CVE-2021-30860)
A small utility to check the presence of known malicious payloads in PDF files.

A program that analyzes PDF files for malformed JBIG2 objects, such as the ones used in FORCEDENTRY

Usage: elegant-bouncer [OPTIONS] <Input file>

Arguments:
  <Input file>  Path to the input PDF file

Options:
  -v, --verbose  Print extra output while parsing
  -a, --analyze  Check if there are any exploited known vulnerabilities
  -c, --create   Create a FORCEDENTRY-like PDF
  -h, --help     Print help information
  -V, --version  Print version information
  ```
### analyze
`--analyze` can be used to analyze a PDF file, it checks if there is the int overflow trigger for CVE-2021-30860.

### create
`--create` is used to create a PDF file from scratch to exploit CVE-2021-30860. WIP.

# References
- [NSO Group iMessage Zero-Click Exploit Captured in the Wild](https://citizenlab.ca/2021/09/forcedentry-nso-group-imessage-zero-click-exploit-captured-in-the-wild/)
- [A deep dive into an NSO zero-click iMessage exploit: Remote Code Execution](https://googleprojectzero.blogspot.com/2021/12/a-deep-dive-into-nso-zero-click.html)
- [FORCEDENTRY: Sandbox Escape](https://googleprojectzero.blogspot.com/2022/03/forcedentry-sandbox-escape.html)
- [@jeffssh POC for CVE-2021-30860](https://twitter.com/jeffssh/status/1474605696020881409)