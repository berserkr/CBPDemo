# -*- coding: utf-8 -*-
"""logging utilities module

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

import logging
import sys
import time, datetime

try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logging.getLogger(__name__).addHandler(NullHandler())

# TODO: to replace this with our logging framework...
logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

def excepthook(*args):
    logging.getLogger(__name__).error('Uncaught exception:', exc_info=args)

sys.excepthook = excepthook