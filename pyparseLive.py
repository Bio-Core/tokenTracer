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


class packetDict:

    def __init__(self, packet, fieldName):
        packetSizeData = str(packet.length)
        sourceIPData   = str(packet['ip'].src)
        sourcePortData = str(packet['tcp'].srcport)
        destIPData     = str(packet['ip'].dst)
        destPortData   = str(packet['tcp'].dstport)

        self.data     = { httpHeader : fieldName, packetSize : packetSizeData, sourceIP : sourceIPData, sourcePort : sourcePortData, \
                           destIP : destIPData, destPort : destPortData }
        
    def printBase(self):
        print('HTTP Protocol:        ' + self.data[httpHeader])
        print('Packet Size:          ' + self.data[packetSize])
        print('Source:               ' + self.data[sourceIP] + ':' + self.data[sourcePort])
        print('Destination:          ' + self.data[destIP] + ':' + self.data[destPort])

    def printRequest(self):
        print('Client Secret:        ' + self.data[clientSecret])
        print('Client Id:            ' + self.data[clientId])
        print('Grant Type:           ' + self.data[grantType])

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

    def loadGrant(self, queryData):
        query = parse_qs(queryData)
        grantTypeData = self.data[grantType]
        
        if grantTypeData == refresh_token:
            refreshTokenData = query[refresh_token][0]
            print('Refresh Token:        ' + str(refreshTokenData))
            self.data[refreshToken] = refreshTokenData

        elif grantTypeData == 'authorization_code':
            codeData = query['code'][0]
            redirectUriData = query['redirect_uri'][0]
            scopeData = query['scope'][0]

            print('Authorization Code:   ' + str(codeData))
            print('Redirect Uri:         ' + str(redirectUriData))
            print('Scope:                ' + str(scopeData))

            self.data[authorizationCode] = codeData
            self.data[rediectUri] = redirectUriData
            self.data[scope] = scopeData
            
        return self.data


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


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', nargs=1, help='Set the interface on which to sniff packets')
    parser.add_argument('-a', '--all', nargs=1, help='Output all HTTP packets captured')
    parser.add_argument('-w', '--write', nargs='?', help='Write to file FILE')
    parser.add_argument('-r', '--read', nargs='?', help='Read from .pcap file FILE')
    #parser.add_argument('-s', '--noprint', help='Surpress printing to stdout')
    #parser.add_argument('--nofile', help='Surpress writing to file')
    args = parser.parse_args()


    # read from a captured file (pcap)
    captureFile = '/srv/pcap1/httpCap4.psml'
    #capture = pyshark.FileCapture(captureFile)
    # capture live from eth0 inside the ga4gh container
    capture = pyshark.LiveCapture(interface='eth0')

    # open a file handle
    packetFile = open('tokenPacket.json', 'w')

    # iterate through all the packets in the capture file
    try:
        for packet in capture.sniff_continuously():
            try:
                if packet != None:

                    # extract the HTTP data payload
                    packetData = packet['http'].file_data

                    # parser for request
                    fieldName = packet['http'].get_field('')
                    regexpPattern = re.compile('POST /auth/realms/.*/protocol/openid-connect/token HTTP')
                    match = regexpPattern.search(fieldName)
                    if match:                
                        packetRequest = packetDict(packet, str(fieldName))  
                        packetRequest.loadQuery(packetData)                  

                        packetRequest.printBase()
                        packetRequest.printRequest()           
                        packetRequest.loadGrant(packetData)
                        print('')

                        jsonString = json.JSONEncoder().encode(packetRequest.data)
                        packetFile.write(jsonString + '\n')
                        continue

                    # parser for response            
                    regexpPattern = re.compile('access_token')
                    match = regexpPattern.search(packetData)

                    # if the access token is found, print the packet information
                    if match:
                        packetResponse = packetDict(packet, str(fieldName))
                        packetResponse.loadToken(packetData)
                        jsonString = json.JSONEncoder().encode(packetResponse.data)
                        packetFile.write(jsonString + '\n') 

                        packetResponse.printBase()
                        packetResponse.printToken()
                        print('')

            except KeyError:
                # go to the next packet if the data is not found
                continue 
            except AttributeError:
                continue
    except RuntimeError:
        # exit upon a CTRL+C signal being given
        packetFile.close()
        exit
 
main()


