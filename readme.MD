# LDAP Nom Nom
*Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)*
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/lkarlslund/ldapnomnom)](https://github.com/lkarlslund/ldapnomnom/releases/latest) ![GitHub all releases](https://img.shields.io/github/downloads/lkarlslund/ldapnomnom/total) ![GitHub Workflow Status](https://img.shields.io/github/workflow/status/lkarlslund/ldapnomnom/Build%20and%20publish%20pre-release)

- Tries to autodetects DC from environment variables on domain joined machines or falls back to machine hostname FDQN DNS suffix
- Reads usernames to test from stdin (default) or file
- Outputs to stdout (default) or file
- Parallelized (defaults to 8 connections)
- Shows progressbar if you're using both input and output files

###Download auto built binaries from [releases](https://github.com/lkarlslund/ldapnomnom/releases) or build and install with this Go command:
```
go install github.com/lkarlslund/ldapnomnom@latest
```

###Usage
```
ldapnomnom [--server ipaddress] [--port number] [--tlsmode notls|tls|starttls] [--input filename] [--output filename [--progressbar]] [--parallel number-of-connections]
```
###Example
```
ldapnomnom --input 10m_usernames.txt --output results.txt --server 192.168.0.11 --parallel 16
```

Look for username lists to feed into this elsewhere - for instance the 10M list from [here](https://github.com/danielmiessler/SecLists/tree/master/Usernames)

##History

During a discussion on Twitter about locating Kerberos services, someone hinted the existance of LDAP Ping requests. They're documented on (Microsofts Open Specifications Pages)[https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/895a7744-aff3-4f64-bcfa-f8c05915d2e9], and it contains pseudo code for how you initiate a LDAP Ping, what parameters it takes and the data returned. It immediately seemed obvious that there is an information leak here that can be abused.

After having released the tool, I can see I'm not the only one to spot this "mistake" which is clearly still around for historic backwards compatibility reasons.

I don't know if event log entries are generated based on this, but I suspect there wouldn't be - feedback is very welcome if you test this. If you want to avoid network level detection as an attacker you should use TLS on port 636 (tool defaults to unencrypted LDAP on port 389).

If you like Active Directory you might also like my attack graph tool [Adalanche](https://github.com/lkarlslund/Adalanche)