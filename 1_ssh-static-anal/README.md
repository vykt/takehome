```
$ cd src && make
$ ./ssh-anal <target> #targets in ../tgt
```

### Summary:

- Reads PE headers.
- Scans all non-blacklisted sections for SSH-specific strings from RFCs 4253 & 8268.
- Attributes weights to discovered strings. If over a given threshold, classifies executable as containing an SSH client.

### Note:

I'm aware it's better to scan the entire file rather than specific sections, but I wanted to show you I can parse PE headers.
