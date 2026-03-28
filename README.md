# SOCKS5 Application Proxy with Secure Authentication
## Overview
A robust SOCKS5 proxy implemented in C, designed for TCP traffic forwarding with secure, Argon2id-hashed password authentication.
The proxy supports multiple user accounts, enforcing one active connection at a time to maintain strict access control. <br>
The project includes:<br>
* A SOCKS5 proxy server that forwards TCP messages between a client and a backend server.<br>
* User authentication is performed by the proxy before establishing the connection.<br>
* A separate registration form allows new users to create accounts.<br>
* Supports secure password storage using Argon2 hashing.<br>
* Includes a Makefile for straightforward compilation and deployment.<br>
## Final Remarks
This setup demonstrates network programming, secure authentication, and socket-based communication, making it a complete example of a lightweight, secure proxy system.
