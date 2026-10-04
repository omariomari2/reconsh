# reconsh

A Bash reconnaissance toolkit for the Snow Day Exploits security lab.
The source groups subdomain discovery, DNS lookup, HTTP probing, port scanning, and public-source research.

## Inspect locally

Use Bash with curl, jq, nmap, dig, whois, and standard Unix text tools.
Show the available commands without scanning a target:

```sh
bash bin/recon.sh check --help
```

The optional C DNS helper is under `native/`.

## Status

An experimental toolkit. The `check` command enters target processing, so the dependency-only path needs correction.
The standalone dependency-check script is empty.
Only run network commands against systems you own or are authorized to assess.

[License](LICENSE)

