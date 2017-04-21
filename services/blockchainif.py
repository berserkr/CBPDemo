# -*- coding: utf-8 -*-
"""Blockchain utilities module

Attributes:

Todo:
    * For module TODOs

"""
__author__ = "Luis Bathen, Gabor Madl"
__copyright__ = "Copyright 2016, IBM"
__credits__ = ["Luis Bathen, Gabor Madl"]
__license__ = "IBM"
__version__ = "0.1"
__maintainer__ = "Luis Bathen"
__email__ = "bathen@us.ibm.com"
__status__ = "Beta"

import urllib2
import json
import ConfigParser
from optparse import OptionParser
import os
import sys
from logger import logger
import requests
import base64

class BlockChain:

    def __init__(self, blockchainconf):
        try:
            # MAIN BODY #
            logger.info('Starting blockchain service...')
            logger.info('chainCodeHash: %s' % os.getenv("chainCodeHash"))
            logger.info('registrarUrl: %s' % os.getenv("registrarUrl"))

            self.chainCodeHash = os.getenv("chainCodeHash") #Config.get('blockchain', 'chainCodeHash')
            self.user = os.getenv("user") #Config.get('blockchain', 'user')
            self.password = os.getenv("password") #Config.get('blockchain', 'password')
            self.chainCodeUrl = os.getenv("chainCodeUrl") #Config.get('blockchain', 'chainCodeUrl')
            self.registrarUrl = os.getenv("registrarUrl") #Config.get('blockchain', 'registrarUrl')

            """
            Config = ConfigParser.ConfigParser()
            Config.read(blockchainconf)
            self.chainCodeHash = Config.get('blockchain','chainCodeHash')
            self.user = Config.get('blockchain','user')
            self.password = Config.get('blockchain','password')
            self.chainCodeUrl = Config.get('blockchain','chainCodeUrl')
            self.registrarUrl = Config.get('blockchain','registrarUrl')
            """
        except Exception, e:
            logger.error("Cannot initialize BlockChain interface. " + repr(e) + "\n")

    # Log into the BlockChain service.
    def login(self):
        logger.info("Initializing registrar connection.")
        loginReq = urllib2.Request(self.registrarUrl)
        loginReq.add_header("Content-type", "application/json")
        loginReq.add_header('Accept', 'application/json')
        loginData = json.dumps({"enrollId":self.user, "enrollSecret":self.password})
        loginReq.add_data(loginData)
        logger.info("Logging in.")
        loginRes = urllib2.urlopen(loginReq)
        return loginRes.read()

    # Read data from the BlockChain.
    def read(self, key):
        """
        logger.info("Creating read query.")
        chainReq = urllib2.Request(self.chainCodeUrl)
        chainReq.add_header("Content-type", "application/json")
        chainReq.add_header('Accept', 'application/json')
        chainData = json.dumps({"jsonrpc":"2.0", "method":"query", "params": {"type": 1,
                "chaincodeID": {"name": self.chainCodeHash}, "ctorMsg": {"function": "read",
                "args": [key]}, "secureContext": self.user}, "id": 2})
        chainReq.add_data(chainData)
        logger.info("Executing read query.")
        chainRes = urllib2.urlopen(chainReq)
        return chainRes.read()        
        """

        url = self.chainCodeUrl
        headers = {'Content-type': 'application/json'}

        data = {"jsonrpc": "2.0", "method": "query", "params": {"type": 1,"chaincodeID": {"name": self.chainCodeHash}, "ctorMsg": {"function": "read", "args": [key]}, "secureContext": self.user}, "id": 2}
  
        logger.info( 'reading \n\t\n\t%s\n\t\n\t from %s' % (json.dumps(data), url) )

        status = requests.post(url,
                            json=data,
                            headers=headers)

        if status and status.status_code == 200:
            logger.info('Successful: %s' % status.json())
            if 'result' in status.json():
                result = status.json()['result']
                if 'message' in result:
                    # if there is a message, decode it w base64 and load it as json
                    message = result['message']
                    data = json.loads(base64.b64decode(message))
                    result['message'] = data
                    return result, False
                else:
                    logger.error(result)
                    return 'Got a result %s, but no message' % result, True
        else:
            logger.error(status)
            return 'Error while reading to blockchain: %s' % status, True

        return 'Error while reading to blockchain: %s' % status, True

    # Write data to the BlockChain.
    def write(self, key, value):      
        """

        {
        "jsonrpc": "2.0",
        "method": "invoke",
        "params": {
            "type": 1,
            "chaincodeID": {
            "name": "35bd67ea0f4597eb0943bb7c4ffac7a57da11b554a72bcfd40c84819ca7f6fe5cd8fa9d7acd8b7519e927d99d3336b02dcd130eb6a2d3659dd69893d325149c6"
            },
            "ctorMsg": {
            "function": "write",
            "args": [
                "test key", "test value"
            ]
            },
            "secureContext": "user_type1_0"
        },
        "id": 0
        }

        """


        url = self.chainCodeUrl
        headers = {'Content-type': 'application/json'}

        # encode data... 
        value = base64.b64encode(json.dumps(value))

        data = {"jsonrpc": "2.0", "method": "invoke", "params": {"type": 1,"chaincodeID": {"name": self.chainCodeHash}, "ctorMsg": {"function": "write", "args": [key, value]}, "secureContext": self.user}, "id": 1}
  
        logger.info( 'writting \n\t\n\t%s\n\t\n\t to %s' % (json.dumps(data), url) )

        status = requests.post(url,
                            json=data,
                            headers=headers)

        if status and status.status_code == 200:
            logger.info('Successful: %s' % status.json())
            if 'result' in status.json():
                return status.json()['result'], False
        else:
            logger.error(status)
            return 'Error while writting to blockchain: %s' % status, True

        return 'Error while writting to blockchain: %s' % status, True
