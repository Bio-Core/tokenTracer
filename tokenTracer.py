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

# set logging level to critical to surpress logger
logging.basicConfig(level=logging.CRITICAL)

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

        self.request = True
        self.refreshRequest = True
        self.response = True
        self.http = True
        self.httpData = True
        self.httpJson = True
        self.printAll = printAll
        self.ofile = ofile
        self.pprint = pprint
        self.packetFile = packetFile
        
        self.data = dict()

        
    def loadAll(self, packet):
        try:
            fieldName = str(packet['http'].get_field(''))   
        except KeyError:
            self.http = False
            return
        
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
            self.httpData = False

        if self.httpData:
            httpQuery = parse_qs(packetData) 

            try:
                clientSecretData = str(httpQuery['client_secret'][0])
            except KeyError:
                self.request = False

            if self.request:
                grantTypeData    = str(httpQuery['grant_type'][0])
                clientIdData     = str(httpQuery['client_id'][0])

                try:
                    refreshTokenData = httpQuery[refresh_token][0]
                except KeyError:
                    codeData         = httpQuery['code'][0]
                    redirectUriData  = httpQuery['redirect_uri'][0]
                    scopeData        = httpQuery['scope'][0]
                    self.refreshRequest = False

            if (not self.request):
                try:
                    httpBody = json.loads(packetData)
                except ValueError:
                    self.httpJson = False
                if self.httpJson:
                    try:
                        httpBody[access_token]
                    except KeyError:
                        self.response = False
                    except TypeError:
                        self.response = False
                    if self.response:       
                        accessTokenData        = str(httpBody[access_token])
                        accessTokenExpiryData  = str(httpBody[access_token_expiry])
                        refreshTokenData       = str(httpBody[refresh_token])
                        refreshTokenExpiryData = str(httpBody[refresh_token_expiry])
                        tokenTypeData          = str(httpBody[token_type])
                        idTokenData            = str(httpBody[id_token])
        
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
                                                                                                                  
    def output(self):
        if self.http and (self.printAll or (self.httpData and (self.request or (self.response and self.httpJson)))):
            if self.pprint:
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

            if self.ofile:
                jsonString = json.JSONEncoder().encode(self.data)
                self.packetFile.write(jsonString + '\n')
        
class packetFilter():

    def __init__(self, packetFile, noFile, noPrint, allPackets):
        self.packetFile = packetFile
        self.pprint     = not noPrint
        self.ofile      = not noFile
        self.allPackets = allPackets

    def load(self, packet):
        pDict = packetDict(self.allPackets, self.pprint, self.ofile, self.packetFile) 
        pDict.loadAll(packet)
        pDict.output()
        
class sniffFrontend:            

    def __init__(self):
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

    def fileCap(self, pFilter, args):
       capture = pyshark.FileCapture(args.iFile, display_filter="http")
        # iterate through all the packets in the capture file
       for packet in capture:
           pFilter.load(packet)

    def liveCap(self, pFilter, args):
        capture = pyshark.LiveCapture(interface=args.interface, display_filter="http")
        try:
            for packet in capture.sniff_continuously():
                pFilter.load(packet)
        except RuntimeError:
            # exit gracefully upon a CTRL+C signal being given
            pass

    def sniffer(self, args):    
        # open a file handle to write to
        if (not args.noFile):
           packetFile = open(args.oFile, 'w')
        else:
           packetFile = None

        pFilter = packetFilter(packetFile, args.noFile, args.noPrint, args.allPackets)

        # either read from a packet capture file
        # or capture packets live from a network interface
        # the network interface is given by args.interface
        if args.iFile:
            self.fileCap(pFilter, args)
        else:
            self.liveCap(pFilter, args)

        if (not args.noFile):
            packetFile.close()
        exit
 
sniffFrontend()


