from tracer import logger
import json

class display:

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


    def outPrint(self, pDict, fieldName, key):
        try:
            data = pDict[key]
        except KeyError:
            #logger.debug("KeyError on key {0}".format(key))
            return None
        print("{0:21}{1}".format(fieldName + ":", data))
        return data

    def prettyPrint(self, pDict):
        '''
        Pretty-prints the packet data to stdout

        Tightly coupled to the packetDict object

        Parameters: None

        Returns: None
        '''
        
        # Use the signature to determine what information 
        # can be printed and in what format 

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


        logger.debug('Pretty-printing...')


        self.outPrint(pDict, "Timestamp", timestamp)
        self.outPrint(pDict, "Transmission Time", "http_time")
        #self.outPrint(pDict, "HTTP Protocol", httpHeader)
        self.outPrint(pDict, "Packet Size", packetSize)
        self.outPrint(pDict, "HTTP Date", "http_date")
        self.outPrint(pDict, "Content Type", "content_type")
        self.outPrint(pDict, "Response Code", "response_code")
        self.outPrint(pDict, "Response Phrase", "response_phrase")
        self.outPrint(pDict, "Source IP", sourceIP)
        self.outPrint(pDict, "Source Port", sourcePort)
        self.outPrint(pDict, "Destination IP", destIP)
        self.outPrint(pDict, "Destination Port", destPort)
        self.outPrint(pDict, "Server", "server")
        #self.outPrint(pDict, "IP Protocol Verison", "ip_protocol")
        self.outPrint(pDict, "Client Secret", clientSecret)
        self.outPrint(pDict, "Client Id", clientId)
        self.outPrint(pDict, "Grant Type", grantType)
        self.outPrint(pDict, "Refresh Token", refreshToken)
        self.outPrint(pDict, "Authorization Code", authorizationCode)
        self.outPrint(pDict, "Redirect Uri", redirectUri)
        self.outPrint(pDict, "Scope", scope)
        self.outPrint(pDict, "Access Token", accessToken)
        self.outPrint(pDict, "Access Token Expiry", accessTokenExpiry)
        self.outPrint(pDict, "Refresh Token", refreshToken)
        self.outPrint(pDict, "Refresh Token Expiry", refreshTokenExpiry)
        self.outPrint(pDict, "Token Type", tokenType)
        self.outPrint(pDict, "Id Token", idToken)
        self.outPrint(pDict, "File Data", "file_data")
        print('')

                                                                                                                  
    def output(self, pDict):
        '''
        Main logging function

        Decides which format to print to stdout

        Parameters: None

        Returns: None
        '''
        logger.debug('Preparing to output...')
        #if self.printAll:
        if self.json:
            logger.debug('Outputting JSON')
            jsonString = json.JSONEncoder().encode(pDict)
            print(jsonString)
        else:
            self.prettyPrint(pDict)
