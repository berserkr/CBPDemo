# -*- coding: utf-8 -*-
"""Factor class

Attributes:

Todo:
    * For module TODOs

"""
__author__ = "Luis Bathen"
__copyright__ = "Copyright 2016, IBM"
__credits__ = ["Luis Bathen"]
__license__ = "IBM"
__version__ = "0.1"
__maintainer__ = "Luis Bathen"
__email__ = "bathen@us.ibm.com"
__status__ = "Beta"

import json

class Factor:
    def __init__(self):
        self.name = None
        self.address = None
        self.private_key = None
        self.public_key = None
        self.salt = None
        self.master = None

    def to_json(self, include_pk=True):
        factor = dict()
        factor['name'] = self.name
        factor['address'] = self.address
        if include_pk:
            factor['private_key'] = self.private_key #self.private_key.to_pem()
            factor['master'] = self.master
        factor['public_key'] = self.public_key
        factor['salt'] = self.salt
        return factor

    def from_json(self, factor):
        self.name = factor['name']
        self.address = factor['address']
        if 'private_key' in factor:
            self.private_key = factor['private_key'] #SigningKey.from_pem(factor['private_key'])
            self.master = factor['master']
        self.public_key = factor['public_key']
        self.salt = factor['salt']
    