"""
Utility class that holds commonly used Bothound functions

"""
import math
import ConfigParser
import numpy as np

from os.path import dirname, abspath
from os import getcwd, chdir

import sys
import glob
import yaml

import MySQLdb

try:
    src_dir = dirname(dirname(abspath(__file__)))
except NameError:
    #the best we can do to hope that we are in the test dir
    src_dir = dirname(getcwd())

sys.path.append(src_dir)

class BothoundTools():
    def connect_to_db(self):
        """
        This connetcion to the db will live for the live time of the
        learn2bantools instance and will be used to save data back to the db
        """
        self.db = MySQLdb.connect(self.db_host, self.db_user, self.db_password)

        #Create cursor object to allow query execution
        self.cur = self.db.cursor(MySQLdb.cursors.DictCursor)
        sql = 'CREATE DATABASE IF NOT EXISTS bothound'
        self.cur.execute(sql)

	    #Connect directly to DB
        self.db = MySQLdb.connect(self.db_host, self.db_user, self.db_password, self.db_name)
        self.cur = self.db.cursor(MySQLdb.cursors.DictCursor)

        self.cur.execute("create table IF NOT EXISTS attack_diary (id INT NOT NULL AUTO_INCREMENT, start_timestamp DATETIME, stop_timestamp DATETIME, dnet VARCHAR(255), host VARCHAR(255), number_of_banjax INT, deflect_hit INT, comment LONGTEXT, PRIMARY KEY(id)) ENGINE=INNODB;")

    def disconnect_from_db(self):
        """
        Close connection to the database
        """
        self.cur.close()
        self.db.close()

    def load_database_config(self):
        """
        Get configuration parameters from the bothound config file
        and from the bothound database
        """
        conf_file_path = src_dir+'/conf/bothound.yaml'
        print conf_file_path

        stram = open(conf_file_path, "r")
        conf = yaml.load(stram)
        
        self.db_user = conf["database"]["user"]
        self.db_password = conf["database"]["password"]
        self.db_host = conf["database"]["host"]
        self.db_name = conf["database"]["name"]

    def random_slicer(self, data_size, train_portion=0.5):
        """
        Return two arrays with random true and false and complement of each
        other, used for slicing a set into trainig and testing

        INPUT:
            data_size: size of the array to return
            train_portion: between 0,1 indicate the portion for the True
                           entry
        """
        from random import random
        random_selector = [random() < train_portion for i in range(0, data_size)]
        complement_selector = np.logical_not(random_selector)

        return random_selector, complement_selector

    def __init__(self):
        #we would like people to able to use the tool object even
        #if they don't have a db so we have no reason to load this
        #config in the constructor
        self.load_database_config()
        pass
