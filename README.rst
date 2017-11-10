==============================
Keycloak Token Tracer Program 
==============================

1.0 Overview
-------------------

This program sniffs for HTTP packets which are requests and responses to and from the token endpoint of the Keycloak authorization server used to server application servers.

The program contains two types of packet filter-parser pairs:

1. One filters and parsers packets that send token requests to the endpoint
2. One filters and parsers packets that are responses to requests to the token endpoint

There are two principal cases in which tokens are transmitted using packets for the OpenID Connect Authentication procedure:

1. Authorization code request
2. Refresh token request 

The Authorization code request occurs once a user has logged into the server through a login screen.

The refresh token request occurs when the user refreshes the webpage after having logged in provided that:
1. The Access Token is expired
2. The Refresh Token is not expired

After the refresh token has expired, the user will be forced to log into the server again using the login page. 
The refresh token generally has a longer expiry than the access token.

1.1 Requirements
-------------------

- Python 2.7+
- tshark
- pyshark

To install the program, one also needs:

- git
- pip

1.2 Usage
--------------------

The token tracer program is invoked as an ordinary python program:

``python tokenTracer.py``

Invoking the token tracer with no command line arguments will cause the program to sniff live on the ethernet interface for all HTTP packets and print them to stdout. 
The program will also write to a file packet.json that will contain a list of JSON objects representing each packet that was printed.
The program will only print/write packets that satisfy its filters. There are two types of packets that it will print:

1. HTTP POST requests made to the token endpoint
2. HTTP responses containing the access token 

1.3 Command Line Arugments
----------------------------

+--------------+------------+-----------------+---------------------------------------------------------------------+
| Variable     | Short Form | Default         | Description                                                         | 
+==============+============+=================+=====================================================================+
| interface    | i          | eth0            | Set the network interface on which the packet sniffer should sniff  |
+--------------+------------+-----------------+---------------------------------------------------------------------+
| input-file   | if         | None            | Set an input file to read packets from                              |
+--------------+------------+-----------------+---------------------------------------------------------------------+
| output-file  | of         | packetFile.json | Specify the name of the JSON output file                            |
+--------------+------------+-----------------+---------------------------------------------------------------------+
| no-file      | nf         | False           | Surpress outputting to a file                                       |
+--------------+------------+-----------------+---------------------------------------------------------------------+
| no-print     | np         | False           | Surpress printing to stdout                                         |
+--------------+------------+-----------------+---------------------------------------------------------------------+
| all          | a          | False           | Print all HTTP packets intercepted                                  |
+--------------+------------+-----------------+---------------------------------------------------------------------+
| json         | j          | False           | Print JSON instead of pretty-printing                               |
+--------------+------------+-----------------+---------------------------------------------------------------------+
| pretty-print | pp         | False           | Write to the output file using pretty-printing instead of JSON      |
+--------------+------------+-----------------+---------------------------------------------------------------------+
| pcap         | pc         | False           | Write in pcap format                                                |
+--------------+------------+-----------------+---------------------------------------------------------------------+
| unfiltered   | u          | False           | Print all packets intercepted (unfiltered)                          |
+--------------+------------+-----------------+---------------------------------------------------------------------+

1.4 Examples
----------------

1.4.1 Example 1: Authorization Code Login Request
==================================================

Run the token tracer program:

``python tokenTracer.py``

Log into the CanDIG server using the default username and password:

The token tracer will output the authorization code request to the token endpoint and its response.

1.4.2 Example 2: Refresh Token Request
==================================================

Log into the Keycloak server as administrator using the default administrator username and password:

Set the Access Token expiry time to 1 minute.

Run the token tracer:

``python tokenTracer.py``

Log into GA4GH Server using the default username and password:

Wait one minute and then refresh the webpage.

The token tracer will print the refresh token request made to the token endpoint and its response,.

1.4.3 Example 3: Input Test File
==================================================

Run the token tracer with the --input-file command line option with the argument "test/test.pcap":

``python tokenTracer.py -if test/test.pcap``

The token tracer will output the packets that match its filters for token endpoint requests and response:


The documentation for this program can be found under /docs.


1.5 External Links
---------------------



The token tracer is designed to sniff for tokens exchanged between application servera and Keycloak. To learn more about Keycloak visit:

http://www.keycloak.org/

This program relies on the pyshark Python sniffer capture library built on top of tshark. To learn more about the library, visit its GitHub repository:

https://github.com/KimiNewt/pyshark

To learn more about tshark and Wireshark, visit Wireshark's website:

https://www.wireshark.org/


