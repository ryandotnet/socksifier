# socksifier
Example DLL code to proxify TCP applications through a SOCKS4 or SOCKS5 proxy. Achieved by hooking the Connect and WSAConnect functions and re-routing them to the proxy address and port. 

- **SOCKS5:**
  - Only username and password authentication is addressed in the example.
  - Only the SOCKS5 CONNECT request is supported.
  - Only IPv4 is supported.
  - No UDP support.
  
- **SOCKS4:**
  - Only the SOCKS4 CONNECT request is supported.
  - Only IPv4 is supported.

# Notes:
This example code is a slightly revised version of a very old project. This code is to help you get started. There are many things missing here such as: 
- Connection timeout handling
- SOCKS reply error handling
- Multiple authentication method support
- UDP support
- BIND support
- IPv6 support
- Domain name support (with DNS resolution).

These things are fairly easy to implement following the [SOCKS5 RFC1928](https://datatracker.ietf.org/doc/html/rfc1928) specification / standard. 
