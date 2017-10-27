#!/usr/bin/python

# this python program iterates through all the packets in a pcap capture file
# if a packet containing an access token is found, the information on that packet is printed

import pyshark
import re
import json
import logging
import argparse

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
rediectUri         = 'rediectUri'
scope              = 'scope'
accessToken        = 'accessToken'
accessTokenExpiry  = 'accessTokenExpiry'
refreshToken       = 'refreshToken'
refreshTokenExpiry = 'refreshTokenExpiry'
tokenType          = 'tokenType'
idToken            = 'idToken'


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

    def __init__(self, packet, fieldName):
        packetSizeData = str(packet.length)
        sourceIPData   = str(packet['ip'].src)
        sourcePortData = str(packet['tcp'].srcport)
        destIPData     = str(packet['ip'].dst)
        destPortData   = str(packet['tcp'].dstport)

        self.data     = { httpHeader : fieldName, packetSize : packetSizeData, sourceIP : sourceIPData,\
                          sourcePort : sourcePortData, destIP : destIPData, destPort : destPortData }

    # outputs the base information common to all HTTP packets        
    def printBase(self):
        print('HTTP Protocol:        ' + self.data[httpHeader])
        print('Packet Size:          ' + self.data[packetSize])
        print('Source:               ' + self.data[sourceIP] + ':' + self.data[sourcePort])
        print('Destination:          ' + self.data[destIP] + ':' + self.data[destPort])


    # prints the information found in token endpoint HTTP requests 
    def printRequest(self):
        print('Client Secret:        ' + self.data[clientSecret])
        print('Client Id:            ' + self.data[clientId])
        print('Grant Type:           ' + self.data[grantType])

    # prints the information found in token endpoint HTTP responses
    def printToken(self):
        print('Access Token:         ' + self.data[accessToken])
        print('Access Token Expiry:  ' + self.data[accessTokenExpiry])
        print('Refresh Token:        ' + self.data[refreshToken])
        print('Refresh Token Expiry: ' + self.data[refreshTokenExpiry])
        print('Token Type:           ' + self.data[tokenType])
        print('Id Token:             ' + self.data[idToken])
        
    def loadQuery(self, queryData):
        query = parse_qs(queryData)

        clientSecretData = str(query['client_secret'][0])
        grantTypeData    = str(query['grant_type'][0])
        clientIdData     = str(query['client_id'][0])

        self.data[clientSecret] = clientSecretData              
        self.data[grantType] = grantTypeData              
        self.data[clientId] = clientIdData                  
        return self.data

    # load grant data from the packet data payload
    # into the packetDict object
    # grant data is derived from the data found in 
    # HTTP request packets to the token endpoint
    # such requests may be based on either an
    # authorization code or a refresh token
    def loadGrant(self, queryData, noPrint):
        query = parse_qs(queryData)
        grantTypeData = self.data[grantType]
        
        # print information pertient to a refresh token request
        if grantTypeData == refresh_token:
            refreshTokenData = query[refresh_token][0]
            if (not noPrint):
                print('Refresh Token:        ' + str(refreshTokenData))
            self.data[refreshToken] = refreshTokenData

        # print the information pertient for an authorization code request
        elif grantTypeData == 'authorization_code':
            codeData = query['code'][0]
            redirectUriData = query['redirect_uri'][0]
            scopeData = query['scope'][0]
            if (not noPrint):
                print('Authorization Code:   ' + str(codeData))
                print('Redirect Uri:         ' + str(redirectUriData))
                print('Scope:                ' + str(scopeData))

            self.data[authorizationCode] = codeData
            self.data[rediectUri] = redirectUriData
            self.data[scope] = scopeData
            
        return self.data

    # stores token data from the packet data payload
    # into the packetDict object
    # token data is derived from the data found
    # in HTTP response packets for the token endpoint
    def loadToken(self, dataStr):
        packetData = json.loads(dataStr)
        accessTokenData = str(packetData[access_token])
        accessTokenExpiryData = str(packetData[access_token_expiry])
        refreshTokenData = str(packetData[refresh_token])
        refreshTokenExpiryData = str(packetData[refresh_token_expiry])
        tokenTypeData = str(packetData[token_type])
        idTokenData = str(packetData[id_token])

        self.data[accessToken] = accessTokenData
        self.data[accessTokenExpiry] = accessTokenExpiryData
        self.data[refreshToken] = refreshTokenData
        self.data[refreshTokenExpiry] = refreshTokenExpiryData
        self.data[tokenType] = tokenTypeData 
        self.data[idToken] = idTokenData     
        return self.data

def packetFilterRequest(packet, packetData, fieldName, noFile, noPrint, packetFile):
    # packet filter and parser for HTTP requests

    # determine if the HTTP packet is a POST request to the token endpoint
    # a regular expression is used that filters for POSTs to any realm's token endpoint
    regexpPattern = re.compile('POST /auth/realms/.*/protocol/openid-connect/token HTTP')
    match = regexpPattern.search(fieldName)

    # if the regular expression matches
    # construct a packetDict object using the matched packet
    if match:
        packetRequest = packetDict(packet, str(fieldName))
        packetRequest.loadQuery(packetData)

        # print the HTTP request information to stdout
        if (not noPrint):
            packetRequest.printBase()
            packetRequest.printRequest()
        # print the specific grant type information
        packetRequest.loadGrant(packetData, noPrint)
        if (not noPrint):
            print('')

        # write to the target output file the packet information
        # as JSON data
        if (not noFile):
            jsonString = json.JSONEncoder().encode(packetRequest.data)
            packetFile.write(jsonString + '\n')
        return True
        #continue
    else:
        return False

def packetHTTPCapture(packet, fieldName, noFile, noPrint, packetFile):
    # packet filter that does no filtering on HTTP packets
    # prints generic information about the packet
    packetResponse = packetDict(packet, str(fieldName))
    if (not noPrint): 
        packetResponse.printBase()
        print('')
    if (not noFile):
        jsonString = json.JSONEncoder().encode(packetResponse.data)
        packetFile.write(jsonString + '\n')
    return True

def packetFilterResponse(packet, packetData, fieldName, noFile, noPrint, packetFile):
    # packet filter and parser for HTTP responses            
    # construct a regular expression to filter for HTTP packets
    # whose data contains an access_token field
    regexpPattern = re.compile('access_token')
    match = regexpPattern.search(packetData)

    # if the access_token field is found inside a packet's data payload, 
    # construct a packetDict object using the matched packet
    # and print the packet information
    if match:
        packetResponse = packetDict(packet, str(fieldName))
        #print(packetData)
        try:
            packetResponse.loadToken(packetData)
        except ValueError:
            packetHTTPCapture(packet, fieldName, noFile, noPrint, packetFile)
        # print to stdout the packet information
        if (not noPrint):
            packetResponse.printBase()
            packetResponse.printToken()
            print('')

        # write the packet information to the target output file
        # as JSON data
        if (not noFile):
           jsonString = json.JSONEncoder().encode(packetResponse.data)
           packetFile.write(jsonString + '\n') 
        return True
    else:
        return False


def packetFilter(packet, allPackets, noFile, noPrint, packetFile):
    try:
        if packet != None:
            # extract the HTTP data payload
            packetData = packet['http'].file_data
            fieldName = packet['http'].get_field('')

            requestMatch = packetFilterRequest(packet, packetData, fieldName, noFile, noPrint, packetFile)
            if (not requestMatch):
                requestMatch = packetFilterResponse(packet, packetData, fieldName, noFile, noPrint, packetFile)
                if (not requestMatch) and allPackets:
                    packetHTTPCapture(packet, fieldName, noFile, noPrint, packetFile)
    except KeyError:
        #go to the next packet if the data is not found
        pass 
    except AttributeError:
        pass

def main():
    # comamnd line argument parser
    parser = argparse.ArgumentParser(description='Traces HTTP requests and responses for authorization tokens from Keycloak for the CanDIG GA4GH server')

    parser.add_argument('-i', '--interface',    default='eth0',                                                     help='Set the interface on which to sniff packets')
    parser.add_argument('-a', '--all',          default=False,              dest='allPackets', action='store_true', help='Output all HTTP packets captured')
    parser.add_argument('-of', '--output-file', default='tokenPacket.json', dest='oFile',                           help='Write to file FILE')
    parser.add_argument('-if', '--input-file',                              dest='iFile',                           help='Read from .pcap file FILE')
    parser.add_argument('-np', '--no-print',    default=False,              dest='noPrint',    action='store_true', help='Surpress printing to stdout')
    parser.add_argument('-nf', '--no-file',     default=False,              dest='noFile',     action='store_true', help='Surpress writing to file')

    # parse for the command line arguments
    args = parser.parse_args()

    # open a file handle to write to
    if (not args.noFile):
       packetFile = open(args.oFile, 'w')

    # if reading from file
    if args.iFile:
       capture = pyshark.FileCapture(args.iFile, display_filter="http")
       for packet in capture:
           packetFilter(packet, args.allPackets, args.noPrint, args.noFile, packetFile)
    # otherwise if capturing live
    else:
        # capture live from eth0 inside the ga4gh container
        capture = pyshark.LiveCapture(interface=args.interface, display_filter="http")
        # iterate through all the packets in the capture file
        try:
            for packet in capture.sniff_continuously():
                packetFilter(packet, args.allPackets, args.noPrint, args.noFile, packetFile)
        except RuntimeError:
            pass

    # exit upon a CTRL+C signal being given
    if (not args.noFile):
        packetFile.close()
    exit
 
main()


