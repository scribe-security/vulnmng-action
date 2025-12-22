# Vulnerability Scan Report
Generated at: 2025-12-22T18:25:37.355802

## Summary
- Total Issues: 12
- new: 12

## Scans
| Target | Last Scan | Tool | Issues Found | Status |
|---|---|---|---|---|
| /scan_target | 2025-12-22T18:24:04.970050 | grype | 0 | clean |
| registry:postgres:alpine | 2025-12-22T18:25:36.149634 | grype | 12 | vulnerable |

## Vulnerabilities
| Target | CVE ID | Package | Version | Severity | Status | Fix Version | Description |
|---|---|---|---|---|---|---|---|
| registry:postgres:alpine | CVE-2025-61723 | stdlib | go1.24.6 | High | new | 1.24.8 | The processing time for parsing some invalid inputs scales non-linearly with respect to the size of ... |
| registry:postgres:alpine | CVE-2025-61725 | stdlib | go1.24.6 | High | new | 1.24.8 | The ParseAddress function constructs domain-literal address components through repeated string conca... |
| registry:postgres:alpine | CVE-2025-58187 | stdlib | go1.24.6 | High | new | 1.24.9 | Due to the design of the name constraint checking algorithm, the processing time of some inputs scal... |
| registry:postgres:alpine | CVE-2025-58188 | stdlib | go1.24.6 | High | new | 1.24.8 | Validating certificate chains which contain DSA public keys can cause programs to panic, due to a in... |
| registry:postgres:alpine | CVE-2025-61729 | stdlib | go1.24.6 | High | new | 1.24.11 | Within HostnameError.Error(), when constructing an error string, there is no limit to the number of ... |
| registry:postgres:alpine | CVE-2025-58185 | stdlib | go1.24.6 | Medium | new | 1.24.8 | Parsing a maliciously crafted DER payload could allocate large amounts of memory, causing memory exh... |
| registry:postgres:alpine | CVE-2025-58186 | stdlib | go1.24.6 | Medium | new | 1.24.8 | Despite HTTP headers having a default limit of 1MB, the number of cookies that can be parsed does no... |
| registry:postgres:alpine | CVE-2025-61724 | stdlib | go1.24.6 | Medium | new | 1.24.8 | The Reader.ReadResponse function constructs a response string through repeated string concatenation ... |
| registry:postgres:alpine | CVE-2025-47912 | stdlib | go1.24.6 | Medium | new | 1.24.8 | The Parse function permits values other than IPv6 addresses to be included in square brackets within... |
| registry:postgres:alpine | CVE-2025-58189 | stdlib | go1.24.6 | Medium | new | 1.24.8 | When Conn.Handshake fails during ALPN negotiation the error contains attacker controlled information... |
| registry:postgres:alpine | CVE-2025-58183 | stdlib | go1.24.6 | Medium | new | 1.24.8 | tar.Reader does not set a maximum size on the number of sparse region data blocks in GNU tar pax 1.0... |
| registry:postgres:alpine | CVE-2025-61727 | stdlib | go1.24.6 | Medium | new | 1.24.11 | An excluded subdomain constraint in a certificate chain does not restrict the usage of wildcard SANs... |
