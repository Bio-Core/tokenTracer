#!/usr/bin/python
'''
This python program iterates through all the packets in a pcap capture file
If a packet containing an access token is found, the information on that packet is printed
'''
import pyshark
import re
import json
import logging
import argparse
import datetime
import sys
import inspect

from urlparse import parse_qs

# set logging level to CRITICAL to surpress logger
# set logging level to DEBUG to view debug statements
# in production, the logger MUST be set to CRITICAL
logLevel = logging.CRITICAL
#logLevel = logging.DEBUG

logging.basicConfig(level=logLevel)

logger = logging.getLogger()

# global json data fields:

access_token         = 'access_token'
access_token_expiry  = 'expires_in'
refresh_token        = 'refresh_token'
refresh_token_expiry = 'refresh_expires_in'
token_type           = 'token_type'
id_token             = 'id_token'
not_before_policy    = 'not-before-policy'
session_state        = 'session_state'
packetSize           = 'packetSize'
sourceIP             = 'sourceIP'
destIP               = 'destIP'
destPort             = 'destPort'
sourcePort           = 'sourcePort'
clientSecret         = 'clientSecret'
grantType            = 'grantType'
clientId             = 'clientId'
httpHeader           = 'httpHeader'
refreshToken         = 'refreshToken'
authorizationCode    = 'authorizationCode'
redirectUri          = 'redirectUri'
scope                = 'scope'
accessToken          = 'accessToken'
accessTokenExpiry    = 'accessTokenExpiry'
refreshToken         = 'refreshToken'
refreshTokenExpiry   = 'refreshTokenExpiry'
tokenType            = 'tokenType'
idToken              = 'idToken'
timestamp            = 'timestamp'

class packetDict:
    '''
    The class for containing packet information
    represents the information stored in an individual HTTP packet
    an instance of this class exists for every HTTP packet found

    All packetDicts store:
    - the packet top level header
    - the packet size
    - the source IP address
    - the source port number
    - the destination IP address
    - the destination port number

    This information is contained inside 
    a data dictionary called data
    '''

    def __init__(self, printAll, jsonFormat):
        '''
        Initializes the attributes of the packetDict object

        Starts the packet dict with an empty dictionary

        The constructor for the packetDict class
        takes a packet object and a fieldName 
        The field name is the first line of the header
        which details the HTTP method and URL

        Parameters:

        boolean printAll - If True, print all intercepted HTTP packets
        boolean jsonFormat - If True, print to stdout in newline-separated JSON objects 
                             If False, print to stdout in pretty-printed format
                             Pretty-printed format uses newline-separated key-value pairs
                             whose keys are separated from their values by a colon and whitespace.

        Returns: packetDict
        '''
        self.printAll = printAll
        self.json = jsonFormat

        self.data = dict()

        # set the initial packet signature
        self.request = True
        self.refreshRequest = True
        self.response = True
        self.http = True
        self.httpData = True
        self.httpJson = True

        
    def loadAll(self, packet):
        '''
        Loads data from the packet into the dictionary

        Parameters:

        packet

        Returns: None
        '''
        # reset the initial packet signature
        self.request = True
        self.refreshRequest = True
        self.response = True
        self.http = True
        self.httpData = True
        self.httpJson = True

        # we assume all packets are HTTP packets
        # as pyshark has been set to filter for HTTP
        # packets in the capturer

        # test if the HTTP packet contains a header

        if not packet:
            return 

        logging.debug('Processing HTTP packet...')
        try:
            fieldName = str(packet['http'].get_field(''))   
        except KeyError:
            logging.debug('KeyError: No header field')
            self.http = False
            return
        
        logging.debug('Loading base data')

        # load common packet information
        # all packets intecepted should contain 
        # these layers and associated fields

        # abort should the http packet be malformed
        # the packet is malformed if it is missing
        # these fields

        try:
            fieldName = str(packet['http'].get_field(''))
            packetSizeData = str(packet.length)
            sourceIPData   = str(packet['ip'].src)
            sourcePortData = str(packet['tcp'].srcport)
            destIPData     = str(packet['ip'].dst)
            destPortData   = str(packet['tcp'].dstport)
        except AttributeError:
            logging.debug("AttributeError: Malformed HTTP packet: Missing Field!")
            return
        except KeyError:
            logging.debug("KeyError: Malformed HTTP Packet: Missing Layer!")
            return

        try:
            packetTime = str(packet.sniff_time)
        except TypeError:
            logging.debug("TypeError: Malformed Timestamp!")
            return

        # test if the HTTP packet contains a payload body
 
        try:
            packetData = packet['http'].file_data
        except AttributeError:
            logging.debug('AttributeError: No payload body for packet')
            self.httpData = False

        if self.httpData:
            httpQuery = parse_qs(packetData) 

            # test if the data payload contains a client secret

            try:
                clientSecretData = str(httpQuery['client_secret'][0])
            except KeyError:
                logging.debug('KeyError: No client secret found')
                self.request = False

            if self.request:
                grantTypeData    = str(httpQuery['grant_type'][0])
                clientIdData     = str(httpQuery['client_id'][0])

                try:
                    refreshTokenData = httpQuery[refresh_token][0]
                except KeyError:
                    logging.debug('KeyError: No refresh token found')
                    codeData         = httpQuery['code'][0]
                    redirectUriData  = httpQuery['redirect_uri'][0]
                    scopeData        = httpQuery['scope'][0]
                    self.refreshRequest = False

           # If the packet is not a request for tokens
           # test if the packet is a response 
           # to such a request:

           # Test if the packet data is in JSON format
           # and if so, test if the packet data contains
           # an access token

            if (not self.request):
                try:
                    httpBody = json.loads(packetData)
                except ValueError:
                    logging.debug('ValueError: Not JSON format')
                    self.httpJson = False
                if self.httpJson:
                    try:
                        httpBody[access_token]
                    except KeyError:
                        logging.debug('KeyError: Access token not found')
                        self.response = False
                    except TypeError:
                        self.response = False
                        logging.debug('TypeError')
                    if self.response:       
                        accessTokenData        = str(httpBody[access_token])
                        accessTokenExpiryData  = str(httpBody[access_token_expiry])
                        refreshTokenData       = str(httpBody[refresh_token])
                        refreshTokenExpiryData = str(httpBody[refresh_token_expiry])
                        tokenTypeData          = str(httpBody[token_type])
                        idTokenData            = str(httpBody[id_token])
        
        # Debugging of the packet signature
        # Used to test if the filters are working

        logging.debug('Parsing complete: Assembling dictionary...')
        logging.debug('Data signature:')
        logging.debug('HTTP Data : ' + str(self.httpData))
        logging.debug('Request : ' + str(self.request))
        logging.debug('Refresh Request : ' + str(self.refreshRequest))
        logging.debug('Response : ' + str(self.response and self.httpJson))

        # Store the locally collected packet data 
        # inside the data dictionary of the object

        # First store the data common to all HTTP packets

        self.data[timestamp]  = packetTime
        self.data[httpHeader] = fieldName
        self.data[packetSize] = packetSizeData
        self.data[sourceIP]   = sourceIPData
        self.data[sourcePort] = sourcePortData
        self.data[destIP]     = destIPData
        self.data[destPort]   = destPortData 

        # Then store the data for token requests and responses
        # if the signature matches        

        if self.httpData:
            if self.request:
                self.data[clientSecret] = clientSecretData
                self.data[grantType]    = grantTypeData
                self.data[clientId]     = clientIdData

                if self.refreshRequest:
                    self.data[refreshToken] = str(refreshTokenData)
                else:
                    self.data[authorizationCode] = str(codeData)
                    self.data[redirectUri]        = str(redirectUriData)
                    self.data[scope]             = str(scopeData)

            if (not self.request) and self.response and self.httpJson:
                self.data[accessToken]        = accessTokenData
                self.data[accessTokenExpiry]  = accessTokenExpiryData
                self.data[refreshToken]       = refreshTokenData
                self.data[refreshTokenExpiry] = refreshTokenExpiryData
                self.data[tokenType]          = tokenTypeData
                self.data[idToken]            = idTokenData
        
        logging.debug(self.data)

    def clearData(self):
        '''
        Clears the data dictionary of the packetDict object

        Clearing the di ctioanry enables a new packet to be loaded
        Otherwise, the new and old packet information can mix and result 
        in a malformed data structure

        Parameters: None

        Returns: None
        '''
        logging.debug('Clearing dictionary...')
        self.data.clear()

    def prettyPrint(self):
        '''
        Pretty-prints the packet data to stdout

        Tightly coupled to the packetDict object

        Parameters: None

        Returns: None
        '''
        
        # Use the signature to determine what information 
        # can be printed and in what format 

        logging.debug('Pretty-printing...')

        try:
            print('Timestamp:            ' + self.data[timestamp])
        except KeyError:
            return

        print('HTTP Protocol:        ' + self.data[httpHeader])
        print('Packet Size:          ' + self.data[packetSize])
        print('Source:               ' + self.data[sourceIP] + ':' + self.data[sourcePort])
        print('Destination:          ' + self.data[destIP] + ':' + self.data[destPort])

        if self.httpData:
            if self.request:
                print('Client Secret:        ' + self.data[clientSecret])
                print('Client Id:            ' + self.data[clientId])
                print('Grant Type:           ' + self.data[grantType])

                if self.refreshRequest:
                    print('Refresh Token:        ' + self.data[refreshToken])
                else:
                    print('Authorization Code:   ' + self.data[authorizationCode])
                    print('Redirect Uri:         ' + self.data[redirectUri])
                    print('Scope:                ' + self.data[scope])

            if (not self.request) and self.response and self.httpJson:
                print('Access Token:         ' + self.data[accessToken])
                print('Access Token Expiry:  ' + self.data[accessTokenExpiry])
                print('Refresh Token:        ' + self.data[refreshToken])
                print('Refresh Token Expiry: ' + self.data[refreshTokenExpiry])
                print('Token Type:           ' + self.data[tokenType])
                print('Id Token:             ' + self.data[idToken])

        print('')

                                                                                                                  
    def output(self):
        '''
        Main logging function

        Decides which format to print to stdout

        Parameters: None

        Returns: None
        '''
        logging.debug('Preparing to output...')
        if self.http and (self.printAll or (self.httpData and (self.request or (self.response and self.httpJson)))):
            if self.json:
                logging.debug('Outputting JSON')
                jsonString = json.JSONEncoder().encode(self.data)
                print(jsonString)
            else:
                self.prettyPrint()

        
class sniffFrontend:            
    '''
    The frontend class establishes the command line parser and contains the packet capturer

    The frontend prepares a packetDict object that is loaded with packets

    +----------------------------------------------+
    |frontend                                      |
    |                                              |
    | +------------------+                         |
    | |commandLineParser |                         |
    | +------------------+                         |
    |         |                                    |
    | +------------------+                         |
    | |sniffer           |                         | 
    | +------------------+                         |
    |         |                                    |
    |         +-----------------------+            |
    |         |                       |            |
    |         \/                      \/           |
    | +-----------------+      +--------------+    |     +------------+
    | |interfaceCapturer|      | fileCapturer |    | <-> | packetDict |
    | +-----------------+      +--------------+    |     +------------+
    +----------------------------------------------+ 
             /\
    eth0     |                     +----+
    +--      |                     |JSON| 
    |--------+                     |    |
    +--                            +----+
    '''

    def start(self):
        '''
        Initializes the command-line arguments parser 

        Loads the sniffing process with the command line arguments

        Parameters: None
        
        Returns: None
        '''
        args = self.argParse(sys.argv[1:])
        self.sniffer(args)

    
    def argParse(self, cmdArgs):
        '''
        Parsers the command line for optional arguments
        
        Returns an object that holds the command line arguments as attributes

        Parameters:

        cmdArgs

        Returns:

        argObject args - The object containing the command line arguments as attributes mapped with their values
        '''
        # command line argument parser
        descLine = 'Outputs a live trace of intercepted HTTP requests and responses for Keycloak authorization tokens.'
        parser = argparse.ArgumentParser(description=descLine)

        argList = [['-i',  '--interface',   'eth0',             
                    'interface',  'store',      'Set the interface on which to sniff packets.'],
                   ['-a',  '--all',         False,              
                    'allPackets', 'store_true', 'Output all HTTP packets captured.'           ],
                   ['-f', '--file',  None,               
                    'iFile',      'store',      'Read from .pcap input file IFILE.'                  ],
                   ['-j',  '--json',        False,               
                    'jsonFormat', 'store_true', 'Output in JSON format.'                      ]]

        for subList in argList:
            parser.add_argument(subList[0], subList[1], default=subList[2], dest=subList[3], action=subList[4], help=subList[5])

        # parse for the command line arguments
        args = parser.parse_args(cmdArgs)
        return args


    def load(self, packet):
        '''
        Loads a packet into the packetDictionary object for processing and logging output

        Parameters: 

        Packet packet - the pyshark Packet object (pyshark.packet.packet.Packet)

        Returns: None
        '''
        self.pDict.loadAll(packet)
        self.pDict.output()
        self.pDict.clearData()


    def fileCap(self, args):
        '''
        Captures from an input packet capture (pcap) file

        Parameters:

        argObject args - The object containing the command line arguments as attributes mapped with their values 

        Returns: None       
        '''
        capture = pyshark.FileCapture(args.iFile, display_filter="http")
        # iterate through all the packets in the capture file
        for packet in capture:
            #logging.debug(type(packet.ip))
            #members = inspect.getmembers(packet.ip)
            #logging.debug(members)
            logging.debug(packet)
            self.load(packet)


    def liveCap(self, args):
        '''
        Captures from a live network interface

        Parameters:

        argObject args - The object containing the command line arguments as attributes mapped with their values 

        Returns: None
        '''
        capture = pyshark.LiveCapture(interface=args.interface, display_filter="http")
        try:
            for packet in capture.sniff_continuously():
                logging.debug(packet)
                self.load(packet)
        except RuntimeError:
            # exit gracefully upon a CTRL+C signal being given
            return


    def sniffer(self, args):    
        '''
        Configures the packet sniffer based on the command line arguments args

        Decides based on args whether the sniff live or from a file
        Creates the base pDict object based on args

        Parameters: 

        argObject args - The object containing the command line arguments as attributes mapped with their values

        Returns: None
        '''
        self.pDict = packetDict(args.allPackets, args.jsonFormat) 

        # either read from a packet capture file
        # or capture packets live from a network interface
        # the network interface is given by args.interface
        if args.iFile:
            self.fileCap(args)
        else:
            self.liveCap(args)
        exit


def main():
    # create the frontend
    sniffer = sniffFrontend()
    # start the packet sniffing process
    sniffer.start()

# if the module is run directly 
# as a script (not imported)
if __name__ == "__main__":
    main()
