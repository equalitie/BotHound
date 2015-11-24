"""
BotnetClassifier

This class is getting the database (table) of sniffed data
runner a unsupervisor on them and classfies the attack

AUTHORS: vmon, ludost (C) Equalit.ie Nov 2015: Initial version

"""
import logging

from collections import OrderedDict

# Gets the instance of the logger.
logging = logging.getLogger("fail2ban.filter")

class BotnetClassifier(object):
    """
    For now get called compute the center of the attack and 
    put it in the log plus the quality of classfication
    """

    def __init__(self):
        """
        Calls the parent constructor then initializes a ip_dictionary
        """
        pass

    def classify(self, ip_database):
        """
        Receive the ip_database and compute the
        center of the cluster and output the quality 
        of the classfication
        """
        pass
