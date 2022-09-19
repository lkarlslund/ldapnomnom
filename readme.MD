# LDAP Nom Nom
Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)

- Autodetects DCs on domain joined machines. A bit moot, as you can just dump usernames with authenticated LDAP, but included for completeness
- Reads usernames to test from stdin or file
- Outputs to stdout or file
- Parallelized, defaults to 8 connections
- Shows progressbar if you're using both input and output files

Installation, requires Go:
```
go install github.com/lkarlslund/ldapnomnom@latest
```

Usage
```
ldapnomnom [--server ipaddress] [--port number] [--tlsmode notls|tls|starttls] [--input filename] [--output filename [--progressbar]] [--parallel number-of-connections]
```
Example:
```
ldapnomnom --input 10m_usernames.txt --output results.txt --server 192.168.0.11 --parallel 16
```

Look for username lists to feed into this elsewhere - for instance the 10M list from [here](https://github.com/danielmiessler/SecLists/tree/master/Usernames)

If you like Active Directory you might also like my attack graph tool [Adalanche](https://github.com/lkarlslund/Adalanche)
