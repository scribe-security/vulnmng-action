# Vulnerability Scan Report
Generated at: 2025-12-23T08:06:16.653028

## Summary
- Total Issues: 12
- status:false-positive: 1
- status:new: 11

## Scans
| Target | Last Scan | Tool | Issues Found | Status |
|---|---|---|---|---|
| /scan_target | 2025-12-23T06:00:20.504189 | grype | 0 | clean |
| registry:postgres:alpine | 2025-12-23T06:01:45.662501 | grype | 12 | vulnerable |

## Vulnerabilities
| Target | CVE ID | Package | Version | Severity | Status | Fix Version | User Comment | Description |
|---|---|---|---|---|---|---|---|---|
| registry:postgres:alpine | CVE-2025-61725 | stdlib | go1.24.6 | High | status:new | 1.24.8 |  | The ParseAddress function constructs domain-literal address components through r... |
| registry:postgres:alpine | CVE-2025-58187 | stdlib | go1.24.6 | High | status:new | 1.24.9 |  | Due to the design of the name constraint checking algorithm, the processing time... |
| registry:postgres:alpine | CVE-2025-58188 | stdlib | go1.24.6 | High | status:new | 1.24.8 |  | Validating certificate chains which contain DSA public keys can cause programs t... |
| registry:postgres:alpine | CVE-2025-61729 | stdlib | go1.24.6 | High | status:new | 1.24.11 |  | Within HostnameError.Error(), when constructing an error string, there is no lim... |
| registry:postgres:alpine | CVE-2025-58185 | stdlib | go1.24.6 | Medium | status:new | 1.24.8 |  | Parsing a maliciously crafted DER payload could allocate large amounts of memory... |
| registry:postgres:alpine | CVE-2025-58186 | stdlib | go1.24.6 | Medium | status:new | 1.24.8 |  | Despite HTTP headers having a default limit of 1MB, the number of cookies that c... |
| registry:postgres:alpine | CVE-2025-61724 | stdlib | go1.24.6 | Medium | status:new | 1.24.8 |  | The Reader.ReadResponse function constructs a response string through repeated s... |
| registry:postgres:alpine | CVE-2025-47912 | stdlib | go1.24.6 | Medium | status:new | 1.24.8 |  | The Parse function permits values other than IPv6 addresses to be included in sq... |
| registry:postgres:alpine | CVE-2025-58189 | stdlib | go1.24.6 | Medium | status:new | 1.24.8 |  | When Conn.Handshake fails during ALPN negotiation the error contains attacker co... |
| registry:postgres:alpine | CVE-2025-58183 | stdlib | go1.24.6 | Medium | status:new | 1.24.8 |  | tar.Reader does not set a maximum size on the number of sparse region data block... |
| registry:postgres:alpine | CVE-2025-61727 | stdlib | go1.24.6 | Medium | status:new | 1.24.11 |  | An excluded subdomain constraint in a certificate chain does not restrict the us... |
| registry:postgres:alpine | CVE-2025-61723 | stdlib | go1.24.6 | High | status:false-positive | 1.24.8 | The vulnerability does not exist in version actual... | The processing time for parsing some invalid inputs scales non-linearly with res... |
