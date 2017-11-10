#!/usr/bin/python

# this python program iterates through all the packets in a pcap capture file
# if a packet containing an access token is found, the information on that packet is printed

import pyshark
import re
import json
import logging
import argparse
import datetime

from urlparse import parse_qs

# set logging level to CRITICAL to surpress logger
# set logging level to DEBUG to view debug statements
# in production, the logger MUST be set to CRITICAL
logging.basicConfig(level=logging.CRITICAL)

logger = logging.getLogger()

# json data fields:

access_token         = 'access_token'
access_token_expiry  = 'expires_in'
refresh_token        = 'refresh_token'
refresh_token_expiry = 'refresh_expires_in'
token_type           = 'token_type'
id_token             = 'id_token'
not_before_policy    = 'not-before-policy'
session_state        = 'session_state'

packetSize         = 'packetSize'
sourceIP           = 'sourceIP'
destIP             = 'destIP'
destPort           = 'destPort'
sourcePort         = 'sourcePort'
clientSecret       = 'clientSecret'
grantType          = 'grantType'
clientId           = 'clientId'
httpHeader         = 'HTTP Header'
refreshToken       = 'refreshToken'
authorizationCode  = 'authorizationCode'
redirectUri         = 'redirectUri'
scope              = 'scope'
accessToken        = 'accessToken'
accessTokenExpiry  = 'accessTokenExpiry'
refreshToken       = 'refreshToken'
refreshTokenExpiry = 'refreshTokenExpiry'
tokenType          = 'tokenType'
idToken            = 'idToken'
timestamp          = 'timestamp'

# the class for containing packet information
# represents the information stored in an individual HTTP packet
# an instance of this class exists for every HTTP packet found
class packetDict:

    # constructor for the packetDict class
    # takes a packet object and a fieldName 
    # the field name is the first line of the header
    # which details the HTTP method and URL

    # all packetDicts store:
    # - the packet top level header
    # - the packet size
    # - the source IP address
    # - the source port number
    # - the destination IP address
    # - the destination port number

    # this information is contained inside a data dictionary
    # called data

    def __init__(self, printAll, pprint, ofile, packetFile):
        '''
        Initializes the attributes of the packetDict object

        Starts the packet dict with an empty dictionary
        '''

        self.printAll = printAll
        self.ofile = ofile
        self.pprint = pprint
        self.packetFile = packetFile

        self.data = dict()

        
    def loadAll(self, packet):
        '''
        Loads data from the packet into the dictionary
        '''

        # set/reset the packet signature
        self.request = True
        self.refreshRequest = True
        self.response = True
        self.http = True
        self.httpData = True
        self.httpJson = True

        logging.debug('Processing HTTP packet...')
        try:
            fieldName = str(packet['http'].get_field(''))   
        except KeyError:
            logging.debug('KeyError: No header field')
            self.http = False
            return
        
        logging.debug('Loading base data')
        fieldName = str(packet['http'].get_field(''))
        packetSizeData = str(packet.length)
        sourceIPData   = str(packet['ip'].src)
        sourcePortData = str(packet['tcp'].srcport)
        destIPData     = str(packet['ip'].dst)
        destPortData   = str(packet['tcp'].dstport)
        packetTime     = str(packet.sniff_time)

        try:
            packetData = packet['http'].file_data
        except AttributeError:
            logging.debug('AttributeError: No payload body for packet')
            self.httpData = False

        if self.httpData:
            httpQuery = parse_qs(packetData) 

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
        
        logging.debug('Parsing complete: Assembling dictionary...')
        logging.debug('Data signature:')
        logging.debug('HTTP Data : ' + str(self.httpData))
        logging.debug('Request : ' + str(self.request))
        logging.debug('Refresh Request : ' + str(self.refreshRequest))
        logging.debug('Response : ' + str(self.response and self.httpJson))

        self.data[timestamp]  = packetTime
        self.data[httpHeader] = fieldName
        self.data[packetSize] = packetSizeData
        self.data[sourceIP]   = sourceIPData
        self.data[sourcePort] = sourcePortData
        self.data[destIP]     = destIPData
        self.data[destPort]   = destPortData 

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
        '''
        logging.debug('Clearing dictionary...')
        self.data.clear()

    def prettyPrint(self):
        '''
        Pretty-prints the packet data to stdout

        Tightly coupled to the packetDict object
        '''
        logging.debug('Pretty-printing...')
        print('Timestamp:            ' + self.data[timestamp])
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

        Decides whether to print to stdout or to a file
        '''
        logging.debug('Preparing to output...')
        if self.http and (self.printAll or (self.httpData and (self.request or (self.response and self.httpJson)))):
            if self.pprint:
                self.prettyPrint()

            if self.ofile:
                logging.debug('Writing to file...')
                jsonString = json.JSONEncoder().encode(self.data)
                self.packetFile.write(jsonString + '\n')
        
        
class sniffFrontend:            

    def __init__(self):
        '''
        Constructor for the sniffFrontend object
  
        Initializes the command-line arguments parser 
        Loads the sniffing process with the command line arguments
        '''
        args = self.argLine()
        self.sniffer(args)

    
    def argLine(self):
        # command line argument parser
        parser = argparse.ArgumentParser(description='Traces HTTP requests and responses for authorization tokens from Keycloak for the CanDIG GA4GH server')

        argList = [['-i',  '--interface',   'eth0',             'interface',  'store',      'Set the interface on which to sniff packets'],
                   ['-a',  '--all',         False,              'allPackets', 'store_true', 'Output all HTTP packets captured'           ],
                   ['-of', '--output-file', 'tokenPacket.json', 'oFile',      'store',      'Write to file FILE'                         ],
                   ['-if', '--input-file',  None,               'iFile',      'store',      'Read from .pcap file FILE'                  ],
                   ['-np', '--no-print',    False,              'noPrint',    'store_true', 'Surpress printing to stdout'                ],
                   ['-nf', '--no-file',     False,              'noFile',     'store_true', 'Surpress writing to file'                   ]]

        for subList in argList:
            parser.add_argument(subList[0], subList[1], default=subList[2], dest=subList[3], action=subList[4], help=subList[5])

        # parse for the command line arguments
        args = parser.parse_args()
        return args


    def load(self, packet):
        '''
        Loads a packet into the packetDictionary object for processing and logging output
        '''
        self.pDict.loadAll(packet)
        self.pDict.output()
        self.pDict.clearData()


    def fileCap(self, args):
       '''
       Captures from an input packet capture (pcap) file
       '''
       capture = pyshark.FileCapture(args.iFile, display_filter="http")
        # iterate through all the packets in the capture file
       for packet in capture:
           logging.debug(packet)
           self.load(packet)


    def liveCap(self, args):
        '''
        Captures from a live network interface
        '''
        capture = pyshark.LiveCapture(interface=args.interface, display_filter="http")
        try:
            for packet in capture.sniff_continuously():
                logging.debug(packet)
                self.load(packet)
        except RuntimeError:
            # exit gracefully upon a CTRL+C signal being given
            pass


    def sniffer(self, args):    
        '''
        Configures the packet sniffer based on the command line arguments args

        Decides based on args whether the sniff live or from a file
        Creates the base pDict object based on args
        '''
        # open a file handle to write to
        if (not args.noFile):
           self.packetFile = open(args.oFile, 'w')
        else:
           self.packetFile = None

        #self.packetFile = args.packetFile
        self.pprint     = not args.noPrint
        self.ofile      = not args.noFile
        self.allPackets = args.allPackets

        self.pDict = packetDict(self.allPackets, self.pprint, self.ofile, self.packetFile) 

        # either read from a packet capture file
        # or capture packets live from a network interface
        # the network interface is given by args.interface
        if args.iFile:
            self.fileCap(args)
        else:
            self.liveCap(args)

        if (not args.noFile):
            self.packetFile.close()
        exit



if __name__ == "__main__":
    sniffFrontend()


