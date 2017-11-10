=====================
Token Tracer Design
=====================

The token tracer is a small Python program that intercepts HTTP packets.
The tracer is designed with two filters used to capture request-response pairs to and from the Keycloak server for tokens during the authentication progress.
These two filters may be deactivated using the -all option. 

The token tracer  may be used for network debugging and logging purposes. 

The token tracer is structured as a single Python module.

1.0 Class Structure
---------------------

The token tracer program is designed with two classes:

1. Base class
2. Packet class

The base class is designed to capture command line arguments and create the capture object from which packet data is derived. 

This packet data is passed into individual packet classes. The packet classes also recieve the command line arguments. The packet classes use the command line arguments 
to decide how to filter the data as it is structured for output. Once the filtered data is finalized into a Python dictionary, the dictionary is either pretty-printed by the packet object or written to a file. 


UML diagram of the two!

1.1 Command Line Arguments
----------------------------
To implement command line arguments, the token tracer using the Python standard argparse library.

Using the argparse library, a default parser object is constructed.

This parser object is then configured to support the command line arguments provided in dictionary list through a loop.
The loop uses the directionary fields in order to determine what values to pass to the parser add_argument function each time 
it loads an additional command. 

The parser args object is then requested, which causes the token tracer program to search for command line arguments from its invocation on sys.argv. 

Using this args object, the token tracer then decides how to filter the packets.


1.2 Interface Selection
------------------------

From the args object, the program branches between either creating a live capture interface or a file capture interface. It is from this interface that packets are extracted. The interfaces are created using the pyshark library, which in turn uses tshark, the command-line implementation of Wireshark. Hence, in using pyshark, the program requires the system to have tshark installed.

If the capture object is a file, the capture object is looped over for all the packet objects it identitifes. The packet objects are then subject to the same filtration and output process as the  



1.3 Program Structure
-----------------------

The program is subdivided between several sequential functions:

1. Command-Line Parser
2. Configuration
3. Packet Sniffer
4. Packet Parser
5. Packet Logging

The command-line parser retrieves arguments passed over the command-line.

The configuration subdivision decides the setup of the packet sniffer, parser, and logger based on the command-line arguments.
The configuration module starts the packet sniffer upon completion. The program will loop over the three components until termination.

The packet sniffer iterates over packets retrieved from either a live interface or from a packet capture file.
When sniffing from a live interface, the program is kept running through a event loop provided by pyshark that listens for packet events.

The parser attemps to recognize the packet structure and extract as much data as possible into a dictionary object. The parser contains the filters for the packet objects.

The logger will print the dictionary object as either JSON or pretty-print format to either stdout or to an output file.


2.0 Testing
--------------------------

Testing may be done manually or through an automated test suite.


2.1 Manual
------------------------

The token tracer program may be manually tested using either a deployment of application servers along with Keycloak or with a test pcap file. The test pcap file in the test directory can be of some use. 

The program is most vulnerable to crashing in the event that it intercepts a malformed or unexpected packet. This is related to the filter design. The filters must be robust enough so that in the vent any of the fields that they are looking for are missing, the resulting exception is handled gracefully. Ideally, the program should attempt to extract and output as much data as it can, and simply move on to the next field to search for in the event of an exception. 

We can use the "Its easier to ask for permission than forgiveness" idiom and use a series of try statements that abort upon an exception. These exceptions should be as precise as possible, as otherwise the program will become very difficult to verify, maintain, and debug should unintented exceptions be caught and ignored. This replaces the alternative design, which is to use a series of if statements. Given the convoluted nature of the resultant series of if statements, in which we would need an independent series of if statements for every field we wish to look for, using exceptions reduces the amount of code needed. 


2.2 Automated
-------------------