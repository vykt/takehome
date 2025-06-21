```
$ make
$ ./uri-div <URI 1> [URI N]
$ ./test.py
```

### Summary:

- Use regex string provided in RFC 3986 Appendix B (pg. 50-51)
- Split authority into user:pass & host:port components. (limited by regex/DFA)
- Determines if URI is a valid generic URI.
