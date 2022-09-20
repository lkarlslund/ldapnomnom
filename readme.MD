# LDAP Nom Nom

*Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)*

No Windows audit logs generated. High speed ~ up to 10K usernames/server/second - way faster with multiple servers!

[![GitHub all releases](https://img.shields.io/github/downloads/lkarlslund/ldapnomnom/total)](https://github.com/lkarlslund/ldapnomnom/releases) ![GitHub Workflow Status](https://img.shields.io/github/workflow/status/lkarlslund/ldapnomnom/Build%20and%20publish%20pre-release)

- Tries to autodetect DC from environment variables on domain joined machines or falls back to machine hostname FQDN DNS suffix
- Reads usernames to test from stdin (default) or file
- Outputs to stdout (default) or file
- Parallelized, multiple connections to multiple servers (defaults to 8 servers, 8 connections per server)
- Shows progressbar if you're using both input and output files

### Download auto built binaries from [releases](https://github.com/lkarlslund/ldapnomnom/releases) or build and install with this Go command

```go
go install github.com/lkarlslund/ldapnomnom@latest
```

### Usage

```bash
ldapnomnom [--server dc1.domain.suffix[,dc2.domain.suffix] | --dnsdomain domain.suffix] [--port number] [--tlsmode notls|tls|starttls] [--input filename] [--output filename [--progressbar]] [--parallel number-of-connections] [--maxservers number-of-servers] [--maxstrategy fastest|random]
```

### Examples

Connect to up to 32 servers from contoso.local with 16 connections to each - FAAAAAAAST
```bash
ldapnomnom --input 10m_usernames.txt --output multiservers.txt --dnsdomain contoso.local --maxservers 32 --parallel 16
```

Connect to one named server with 4 connections
```bash
ldapnomnom --input 10m_usernames.txt --output results.txt --server 192.168.0.11 --parallel 4
```

Look for username lists to feed into this elsewhere - for instance the 10M list from [here](https://github.com/danielmiessler/SecLists/tree/master/Usernames)

## Detection

- No Windows event logs are generated (tested on Windows 2016 / 2019)
- Requires custom network level monitoring (unencrypted LDAP analysis or traffic volume for LDAPS)

## Mitigation

- None, this is part of the dcLocator stuff
- Rename your administrator account
- Audit accounts for having same password as the username
- Prevent kerberoasting by removing SPNs on as many accounts as possible
- Use long and complex passwords on accounts with SPNs

## History

During a discussion on Twitter about locating Kerberos services, someone hinted the existance of LDAP Ping requests. They're documented on [Microsofts Open Specifications Pages](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/895a7744-aff3-4f64-bcfa-f8c05915d2e9), and it contains pseudo code for how you initiate a LDAP Ping, what parameters it takes and the data returned. It immediately seemed obvious that there is an information leak here that can be abused.

After having released the tool, I can see I'm not the only one to spot this "mistake" which is clearly still around for historic backwards compatibility reasons.

If you want to avoid network level detection as an attacker you should use TLS on port 636 (tool defaults to unencrypted LDAP on port 389).

If you like Active Directory you might also like my attack graph tool [Adalanche](https://github.com/lkarlslund/Adalanche)
