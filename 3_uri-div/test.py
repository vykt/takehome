#!/usr/bin/python3

import subprocess

uri_tup: tuple = (
    "http://www.example.com/path/to/resource?param1=value1&param2=value2#fragment",
    "https://subdomain.example.co.uk:8443/",
    "ftp://user:password@ftp.example.com/file.txt",
    "mailto:user@example.net",
    "//example.org/relative/path",
    "data:text/plain;charset=UTF-8,This%20is%20some%20text",
    "http://192.168.1.100/",
    "http://example.com/path%20with%20spaces/",
    "http://example.com/path?key=value%20with%20spaces",
    "http://example.com/path?key=value&key2=")

def main():
    global uri_tup

    for uri in uri_tup:
        x = subprocess.run(["./uri-div", uri], capture_output=True)
        print(x.stdout.decode("ASCII"))
        
main()
