"""
Utility class that holds commonly used Bothound functions

"""
import numpy as np

import MySQLdb

class BothoundTools():
    def connect_to_db(self):
        """
        This connetcion to the db will live for the live time of the
        learn2bantools instance and will be used to save data back to the db
        """
        self.db = MySQLdb.connect(self.db_host, self.db_user, self.db_password)

        #Create cursor object to allow query execution
        self.cur = self.db.cursor(MySQLdb.cursors.DictCursor)
        sql = 'CREATE DATABASE IF NOT EXISTS ' + self.db_name
        self.cur.execute(sql)

	    #Connect directly to DB
        self.db = MySQLdb.connect(self.db_host, self.db_user, self.db_password, self.db_name)
        self.cur = self.db.cursor(MySQLdb.cursors.DictCursor)

        # ATTACKS table
        self.cur.execute("create table IF NOT EXISTS attacks (id INT NOT NULL AUTO_INCREMENT, "
        "comment LONGTEXT, "
        "PRIMARY KEY(id)) ENGINE=INNODB;")

       # INCIDENTS table
        self.cur.execute("create table IF NOT EXISTS incidents (id INT NOT NULL AUTO_INCREMENT, "
        "id_attack INT NOT NULL,"
        "start DATETIME, "
        "stop DATETIME, "
        "banjax_start DATETIME, "
        "banjax_stop DATETIME, "
        "comment LONGTEXT, "
        "processed BOOL,"
        "PRIMARY KEY(id), INDEX index_attack (id_attack), "
        "FOREIGN KEY (id_attack) REFERENCES attacks(id) ON DELETE CASCADE ) ENGINE=INNODB;")
        
        # SESSIONS table
        self.cur.execute("create table IF NOT EXISTS sessions (id INT NOT NULL AUTO_INCREMENT, "
        "id_incident INT NOT NULL, "
        "cluster_index INT, "
        "IP VARCHAR(45), "
        "request_interval FLOAT, " #Feature Index 1
        "ua_change_rate FLOAT, " #Feature Index 2
        "html2image_ratio FLOAT, " #Feature Index 3
        "variance_request_interval FLOAT, " #Feature Index 4
        "payload_average FLOAT, " #Feature Index 5
        "error_rate FLOAT, " #Feature Index 6
        "request_depth FLOAT, " #Feature Index 7
        "request_depth_std FLOAT, " #Feature Index 8
        "session_length FLOAT, " #Feature Index 9
        "percentage_cons_requests FLOAT," #Feature Index 10
        "coorditate_x FLOAT," #Feature Index 11
        "coorditate_y FLOAT," #Feature Index 12
        "coorditate_z FLOAT," #Feature Index 13
        "PRIMARY KEY(id), INDEX index_incicent (id_incident),  "    
        "FOREIGN KEY (id_incident) REFERENCES incidents(id) ON DELETE CASCADE ) ENGINE=INNODB;")

        # CLUSTERS table
        self.cur.execute("create table IF NOT EXISTS clusters (id INT NOT NULL AUTO_INCREMENT, "
        "id_incident INT NOT NULL, "
        "cluster_index INT NOT NULL, "
        "comment LONGTEXT, "
        "PRIMARY KEY(id), INDEX index_incicent (id_incident),  "    
        "FOREIGN KEY (id_incident) REFERENCES incidents(id) ON DELETE CASCADE ) ENGINE=INNODB;")

    def insert_into_sessons_table(self, incident_id, ip_feature_db):
        insert_sql = "insert into sessions values (" + str(incident_id) + ", 0, " 
        for ip in ip_feature_db:
            features = ip_feature_db[ip]
            insert_sql += "\"" + ip + "\","
            for feature in features:
                insert_sql += str(feature) + ","

        insert_sql = insert_sql[:-1]
        insert_sql += ");"
        
        self.cur.execute(insert_sql)
 
    def disconnect_from_db(self):
        """
        Close connection to the database
        """
        self.cur.close()
        self.db.close()

    def load_database_config(self, database_conf):        
        self.db_user = database_conf["user"]
        self.db_password = database_conf["password"]
        self.db_host = database_conf["host"]
        self.db_name = database_conf["name"]

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

    """
    This method requires installation of the following packages.
    It downloads the entire geo-location database, so its accessible offline. 
    pip install python-geoip
    pip install python-geoip-geolite2
    """
    @staticmethod
    def find_location(ip):
        from geoip import geolite2
        
        match = geolite2.lookup(ip)
        return match.location
    
    """
    Latitude and longitude are polar coordinates
    So to use them as features in KMneas it is recommended to convert them into 
    Cartesian coordinates, so that Euclidean distance between two points makes sense. 
    """
    @staticmethod
    def convert_to_cartesian(location):
        import math
        
        latitude = location[0]
        longitude = location[1]
        # Spherical coordinates in Radians
        longitude_rad = longitude * (2 * math.pi)/360
        latitude_rad = (latitude * 2) * (2 * math.pi)/360
        R = (6378 + 6356)/2
        
        # Cartesian coordinates
        cartesian = {};
        cartesian['x'] = R * math.cos(latitude_rad) * math.cos(longitude_rad)
        cartesian['y'] = R * math.cos(latitude_rad) * math.sin(longitude_rad)
        cartesian['z'] = R * math.sin(latitude_rad)
        return cartesian

    def __init__(self, database_conf):
        #we would like people to able to use the tool object even
        #if they don't have a db so we have no reason to load this
        #config in the constructor
        self.load_database_config(database_conf)
        pass
