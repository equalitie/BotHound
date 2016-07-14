"""
Utility class that holds commonly used Bothound functions

"""
import numpy as np

from sklearn.cluster import DBSCAN
from sklearn.cluster import KMeans
import hashlib, hmac
import MySQLdb, pycountry

from features.src.feature_geo import FeatureGEO
from features.src.feature_deflectee import FeatureDeflectee
from features.src.feature_user_agent import FeatureUserAgent

from util.crypto import encrypt
from util.crypto import decrypt
import pdb
import sys
from sklearn import preprocessing
import datetime
import calendar

class BothoundTools():
    def connect_to_db(self):
        """
        This connetcion to the db will live for the live time of the
        learn2bantools instance and will be used to save data back to the db
        """
        self.db = MySQLdb.connect(host = self.db_host, user = self.db_user, 
            passwd = self.db_password,port = self.db_port, charset='utf8',
            use_unicode=True)

        #Create cursor object to allow query execution
        self.cur = self.db.cursor(MySQLdb.cursors.DictCursor)
        sql = 'CREATE DATABASE IF NOT EXISTS ' + self.db_name
        self.cur.execute(sql)
        self.db.close()

        #Connect directly to DB
        self.db = MySQLdb.connect(host = self.db_host, user = self.db_user, 
            passwd = self.db_password, port = self.db_port, db = self.db_name)
        self.cur = self.db.cursor(MySQLdb.cursors.DictCursor)

        # ATTACKS table
        self.cur.execute("create table IF NOT EXISTS attacks (id INT NOT NULL AUTO_INCREMENT, "
        "comment LONGTEXT, "
        "PRIMARY KEY(id)) ENGINE=INNODB;")

       # INCIDENTS table
        self.cur.execute("create table IF NOT EXISTS incidents (id INT NOT NULL AUTO_INCREMENT, "
        "id_attack INT,"
        "start DATETIME, "
        "stop DATETIME, "
        "banjax_start DATETIME, "
        "banjax_stop DATETIME, "
        "comment LONGTEXT, "
        "process BOOL,"
        "target LONGTEXT,"
        "cluster_index INT,"
        "file_name LONGTEXT, "
        "id_encryption INT,"
        "PRIMARY KEY(id)) "
        "ENGINE=INNODB;")

        # SESSIONS table
        self.cur.execute("create table IF NOT EXISTS sessions (id INT NOT NULL AUTO_INCREMENT, "
        "id_incident INT NOT NULL, "
        "cluster_index INT, "
        "cluster_index2 INT, "
        "IP VARCHAR(45), "
        "IP_ENCRYPTED LONGTEXT, "
        "IP_IV LONGTEXT, "
        "IP_TAG LONGTEXT, "
        "ban BOOL,"
        "attack BOOL,"
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
        "latitude FLOAT," #Feature Index 11
        "longitude FLOAT," #Feature Index 12
        "id_country INT," #Feature Index 13
        "id_deflectee INT," #Feature Index 14

        "PRIMARY KEY(id), INDEX index_incicent (id_incident),  "    
        "FOREIGN KEY (id_incident) REFERENCES incidents(id) ON DELETE CASCADE ) ENGINE=INNODB;")

        # CLUSTERS table
        self.cur.execute("create table IF NOT EXISTS clusters (id INT NOT NULL AUTO_INCREMENT, "
        "id_incident INT NOT NULL, "
        "cluster_index INT NOT NULL, "
        "comment LONGTEXT, "
        "PRIMARY KEY(id), INDEX index_incicent (id_incident),  "
        "FOREIGN KEY (id_incident) REFERENCES incidents(id) ON DELETE CASCADE ) ENGINE=INNODB;")

        # DEFLECTEES table
        self.cur.execute("create table IF NOT EXISTS deflectees (id INT NOT NULL AUTO_INCREMENT, "
        "domain LONGTEXT, "
        "comment LONGTEXT, "
        "PRIMARY KEY(id)) ENGINE=INNODB;")

        # COUNTRIES table
        self.cur.execute("create table IF NOT EXISTS countries (id INT NOT NULL AUTO_INCREMENT, "
        "code LONGTEXT, "
        "name LONGTEXT, "
        "PRIMARY KEY(id)) ENGINE=INNODB;")

        # Intersections table
        self.cur.execute("create table IF NOT EXISTS intersections (id INT NOT NULL AUTO_INCREMENT, "
        "id_incident INT," 
        "id_incident2 INT," 
        "total INT, "
        "intersection FLOAT, " # (length of id_incident)*100/total
        "intersection2 FLOAT, " # (length of id_incident2)*100/total
        "PRIMARY KEY(id), INDEX index_incicent (id_incident),"
        "FOREIGN KEY (id_incident) REFERENCES incidents(id) ON DELETE CASCADE"
        ") ENGINE=INNODB;")

         # user_agent table
        self.cur.execute("create table IF NOT EXISTS user_agents (id INT NOT NULL AUTO_INCREMENT, "
        "ua LONGTEXT, "
        "device_family LONGTEXT,"
        "os_family LONGTEXT,"
        "os_major LONGTEXT,"
        "os_minor LONGTEXT,"
        "os_patch LONGTEXT,"
        "os_patch_minor LONGTEXT,"
        "ua_family LONGTEXT,"
        "ua_major LONGTEXT,"
        "ua_minor LONGTEXT,"
        "ua_patch LONGTEXT,"
        "PRIMARY KEY(id)) ENGINE=INNODB;")

        # session_ua table
        self.cur.execute("create table IF NOT EXISTS session_user_agent (id INT NOT NULL AUTO_INCREMENT, "
        "id_session INT, "
        "id_user_agent INT,"
        "count INT,"
        "INDEX index_ua (id_user_agent), INDEX index_session (id_session),"
        "PRIMARY KEY(id),"
        "FOREIGN KEY (id_session) REFERENCES sessions(id) ON DELETE CASCADE,"
        "FOREIGN KEY (id_user_agent) REFERENCES user_agents(id) ON DELETE CASCADE"
        ") ENGINE=INNODB;")

        # ENCRYPTION table
        self.cur.execute("create table IF NOT EXISTS encryption (id INT NOT NULL AUTO_INCREMENT, "
        "key_hash LONGTEXT, "
        "comment LONGTEXT, "
        "PRIMARY KEY(id)) ENGINE=INNODB;")


    def get_deflectees(self):
        self.cur.execute("select * from deflectees")
        return [dict(elem) for elem in self.cur.fetchall()]

    def get_countries(self):
        self.cur.execute("select * from countries")
        return [dict(elem) for elem in self.cur.fetchall()]

    def update_country_names(self):
        countries = self.get_countries()
        for country in countries:
            #pdb.set_trace()
            if(country['name'] is not None) :
                continue
            try:
                c = pycountry.countries.get(alpha2=country['code'])
            except KeyError:
                continue
            
            if (c is None) :
                continue
            self.cur.execute("update countries set name = %s where code = %s",
                [c.name, country['code']]) 
        self.db.commit()

    """
    Post process features calculated by "lear2bat_feature" class instances
    """
    def post_process(self, ip_feature_db):
        # factorize the deflectees
        ip_feature_db = self.factorize_deflectees(ip_feature_db)

        # factorize the deflectees
        ip_feature_db = self.factorize_countries(ip_feature_db)

        return ip_feature_db

    """
    Replace domain string value in ip_feature_db with the appropriate 
    ID from deflectees table.
    Create new rows in deflectees table if necessary
    """
    def factorize_deflectees(self, ip_feature_db):
        deflectees = self.get_deflectees()

        ids = {}
        for d in deflectees:
            ids[d["domain"]] = d['id']

        feature_index = FeatureDeflectee({},{}).get_index()

        for ip in ip_feature_db:
            features = ip_feature_db[ip]
            domain = features[feature_index] 
            if(isinstance(domain, ( int, long ) ) == True):
                continue

            if(domain in ids):
                features[feature_index] = ids[domain]
            else:
                self.cur.execute("insert into deflectees(domain) values ('{}')".format(domain))
                ids[domain] = self.cur.lastrowid
                features[feature_index] = self.cur.lastrowid
                self.db.commit()

        return ip_feature_db
        
    """
    Replace country string value in ip_feature_db with the appropriate 
    ID from countreis table.
    Create new rows in countreis table if necessary
    """
    def factorize_countries(self, ip_feature_db):
        countries = self.get_countries()

        ids = {}
        for c in countries:
            ids[c["code"]] = c['id']

        feature_index = FeatureGEO({},{}).get_index() + 2

        for ip in ip_feature_db:
            features = ip_feature_db[ip]
            country_code = features[feature_index] 
            if(isinstance(country_code, ( int, long ) ) == True):
                continue

            if(country_code in ids):
                features[feature_index] = ids[country_code]
            else:
                country_name = country_code
                cc = None
                try:
                    cc = pycountry.countries.get(alpha2=country_code)
                    country_name = cc.name.encode('ascii','ignore')
                except KeyError:
                    country_name = country_code

                self.cur.execute("insert into countries(code, name) values (%s, %s)", [country_code, country_name])
                ids[country_code] = self.cur.lastrowid
                features[feature_index] = self.cur.lastrowid
                self.db.commit()

        return ip_feature_db

    def delete_sessions(self, id_incident):
        self.cur.execute("DELETE FROM sessions WHERE id_incident = {0}".format(id_incident))
        self.db.commit()

    def add_sessions(self, id_incident, ip_feature_db, banned_ips):
        for ip in ip_feature_db:

            insert_sql = "insert into sessions values (%s,%s,%s,%s,%s,%s,%s,%s,%s"
            features = ip_feature_db[ip]
            for feature in features:
                insert_sql += ",%s"
            insert_sql += ")"

            features = ip_feature_db[ip]
            ip_ascii = ip[0].encode('ascii','ignore')
            ip_enctypted = self.encrypt(ip_ascii)
            ip_hash = self.hash(ip_ascii)

            ua_feature = FeatureUserAgent(None, None)
            ban = 0
            if(banned_ips is not None and ip[0] in banned_ips):
                ban = 1
            values = [0,id_incident,0,0, ip_hash, ip_enctypted[1], ip_enctypted[0], ip_enctypted[2], ban, 0]
            for feature in features:
                if(feature != ua_feature.get_feature_index()):
                    values.append(features[feature])
            #   pdb.set_trace()   
            try:         
                self.cur.execute(insert_sql, values)
                id_session = self.cur.lastrowid
                for key, value in features[ua_feature.get_feature_index()].iteritems():
                    self.cur.execute("select id from user_agents where ua =%s",[key])
                    ids = self.cur.fetchall()
                    if(len(ids) == 0):
                        insert_sql = "INSERT INTO user_agents ("\
                        "id, ua, device_family,os_family,os_major,os_minor,os_patch,os_patch_minor,ua_family,ua_major,ua_minor,ua_patch"\
                        ") VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                        self.cur.execute(insert_sql,[
                            0,key,
                            value["device_family"],
                            value["os_family"],
                            value["os_major"],
                            value["os_minor"],   
                            value["os_patch"],
                            value["os_patch_minor"],
                            value["ua_family"],
                            value["ua_major"],
                            value["ua_minor"],
                            value["ua_patch"]]
                            )
                        id_user_agent = self.cur.lastrowid
                    else:
                        id_user_agent = ids[0]['id']

                    insert_sql = "INSERT INTO session_user_agent ("\
                    "id, id_session, id_user_agent, count"\
                    ") VALUES(%s, %s,%s,%s)"

                    self.cur.execute(insert_sql,[0,id_session, id_user_agent, value["count"]])

            except Exception,e:
                g = 0
                print e

        # update encryption key for this incident
        key_hash = hashlib.sha256(self.db_encryption_key).digest()
        self.cur.execute("select id from encryption where key_hash = %s", key_hash) 
        ids = self.cur.fetchall()
        id_key = 1
        #pdb.set_trace()
        if(len(ids)) > 0: 
            id_key = ids[0]['id']
        else:
            self.cur.execute("insert INTO encryption (id, key_hash) VALUES(%s,%s)", [0, key_hash]) 
            id_key = self.cur.lastrowid
        print "id_key", id_key
        print "id_incident", id_incident
        self.cur.execute("update incidents set id_encryption=%s WHERE id = %s",[id_key,id_incident])

        self.db.commit()

    def get_sessions(self, id_incident):
        self.cur.execute("select * from sessions WHERE id_incident = {0}".format(id_incident))
        return [dict(elem) for elem in self.cur.fetchall()]

    def get_sessions_atack(self, id_incident):
        self.cur.execute("select * from sessions WHERE id_incident = {0} and attack > 0".format(id_incident))
        return [dict(elem) for elem in self.cur.fetchall()]

    def get_banned_ips(self, id_incidents):

        sql_where = " where id_incident in ("
        for id in id_incidents:
            sql_where = sql_where + "{},".format(id)
        sql_where = sql_where[:-1]
        sql_where += ") "

        self.cur.execute("select DISTINCT IP from sessions " +
                sql_where + " and ban > 0")
        return [elem["IP"] for elem in self.cur.fetchall()]
    
    def get_attack_ips(self, id_incidents, id_attack = 0):

        sql_where = " where id_incident in ("
        for id in id_incidents:
            sql_where = sql_where + "{},".format(id)
        sql_where = sql_where[:-1]
        sql_where += ") "

        if id_attack > 0:
            self.cur.execute("select DISTINCT IP from sessions " +
                sql_where + " and attack = {}".format(id_attack))
        else:
            self.cur.execute("select DISTINCT IP from sessions " +
                sql_where + " and attack > 0 ")
        return [elem["IP"] for elem in self.cur.fetchall()]


    def get_ips(self, id_incident, attack = -1):
        if attack >= 0 :
            self.cur.execute("select DISTINCT IP from sessions WHERE id_incident = {} "
                "and attack = {}".format(id_incident, attack))
        else:
            self.cur.execute("select DISTINCT IP from sessions WHERE id_incident = {0} and attack > 0".format(id_incident))

        return [elem["IP"] for elem in self.cur.fetchall()]

    def get_selected_cluster(self, id_incident):
        self.cur.execute("select * from incidents WHERE id = {0}".format(id_incident))
        f = self.cur.fetchall()
        if (len(f) == 0) :
            return -1
        return f["cluster_index"]

    def set_incident_process(self, id, process):
        sql = "update incidents set process={} WHERE id = {}".format(process,id)
        self.cur.execute(sql)
        self.db.commit()

    def get_incidents(self, process):
        self.db.ping()
        self.cur.execute("select * from incidents WHERE "
        "cast(process as unsigned) = %d" % (1 if process else 0))
        res = [dict(elem) for elem in self.cur.fetchall()]
        self.db.commit()
        return res

    def get_incident(self, id):
        self.cur.execute("select * from incidents WHERE id = %d" % id)
        return self.cur.fetchall()

    def update_geo(self, id_incident):
        self.cur.execute("select id, ip from sessions WHERE id_incident = {0}".format(id_incident))
        rows = self.cur.fetchall();
        for row in rows:
            match = FeatureGEO.find_location(row['ip'])
            sql = "update sessions set latitude={}, longitude={}, country='{}' WHERE id = {}".format(match['latitude'], match['longitude'], match['country'], row['id'])
            self.cur.execute(sql)

        self.db.commit()
        return

    def disconnect_from_db(self):
        """
        Close connection to the database
        """
        self.cur.close()
        self.db.close()

    def load_database_config(self, database_conf, elastic_db_conf):
        self.db_user = database_conf["user"]
        self.db_password = database_conf["password"]
        self.db_host = database_conf["host"]
        self.db_name = database_conf["name"]
        if("port" in database_conf):
            self.db_port = database_conf["port"]
        else:
            self.db_port = 3306

        self.db_encryption_key = hashlib.sha256(database_conf["encryption_passphrase"]).digest()
        self.db_hash_key = hashlib.sha256(database_conf["hash_passphrase"]).digest()

        #read elastic search user and password
        self.es_user = elastic_db_conf["user"]
        self.es_password = elastic_db_conf["password"]
        self.es_host = elastic_db_conf["host"]
        if("port" in elastic_db_conf):
            self.es_port = elastic_db_conf["port"]
        else:
            self.es_port = 9200

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
    create a test incident and all the sessions from 
    ../data/feature_db-files.txt
    """
    def get_test_incident(self):

        test_comment = 'Test incident'
        #check if the test incident exists
        self.cur.execute("select id from incidents WHERE comment = '{0}'".format(test_comment))
        for row in self.cur.fetchall():
            print "test incident exists", row['id']
            return row['id']

        print "creating test incident..."

        #new incident record
        sql = "insert into incidents(comment) VALUES('%s')" % (test_comment)
        self.cur.execute(sql)

        id_incident = self.cur.lastrowid
        print "id_incident", id_incident

        filename = '../data/feature_db-files.txt'
        file = open(filename)
        line_number = 15000
        for line in file:
            splitted_line = line.split(') {')

            useful_part = splitted_line[1]
            useful_part = useful_part[:-2]
            new_split = useful_part.split(', ')

            insert_sql = "insert into sessions values (NULL," + str(id_incident) + ", 0, "
            insert_sql += "\"" + str(line_number) + "\","
            line_number = line_number + 1

            insert_sql += "0,0,0,"

            for b in new_split:
               c = b.split(': ')[1]
               insert_sql += str(c) + ","
                
            insert_sql += "0,0,0,0,"
            insert_sql = insert_sql[:-1]
            insert_sql += ");"
            self.cur.execute(insert_sql)

        self.db.commit()
        print "done."
        return id_incident

    """
    Cluster the sessions in the incident.
    Update cluster_index in session table
    Return the sessions with the calculated cluster_index
    """    
    def cluster(self, id_incident):
        sessions = self.get_sessions(id_incident)
        features = [
            "request_interval",
            "ua_change_rate",
            "html2image_ratio",
            "variance_request_interval",
            "payload_average",
            "error_rate",
            "request_depth",
            "request_depth_std",
            "session_length",
            "percentage_cons_requests",
            #"latitude",
            #"longitude"
            ]
        data_set = []
        for session in sessions:
            values = []
            for feature in features:
                values.append(session[feature])
            data_set.append(values)

        if len(data_set) == 0 :
            return

        X = np.array(data_set)

        # Compute DBSCAN
        db = DBSCAN(eps=0.1, min_samples=20).fit(X)
        core_samples_mask = np.zeros_like(db.labels_, dtype=bool)
        core_samples_mask[db.core_sample_indices_] = True
        labels = db.labels_

        # Number of clusters in labels, ignoring noise if present.
        n_clusters_ = len(set(labels)) - (1 if -1 in labels else 0)
        print('Estimated number of clusters: %d' % n_clusters_)

        #update the cluster column in session table
        for session, label in zip(sessions, labels):
            session["cluster_index"] = label
            self.cur.execute('update sessions set cluster_index ={0} '
            'where id={1}'.format(label, session['id']))
        self.db.commit()
        return sessions


    def encrypt(self, data):
        return encrypt(self.db_encryption_key, data, "")

    def decrypt(self, data, data_iv, data_tag):
        return decrypt(self.db_encryption_key, "", data_iv, data, data_tag)

    def hash(self, data):
        return hmac.new(data, self.db_hash_key, hashlib.sha256).digest()

    def encrypt_and_hash(self, data):
        """
        This is mainly for storing IPs so we don't store them 
        in plain, we use hash so each ip converts to the same
        hash so we can get all the sessions related to an ip
        without knowing the ip

        INPUT:: a string containing the sensetive data

        OUTPUT:: (encrypted_sensetive_data, 
                  keyed_hash_of_sensetive_data)
        """
        return (self.encrypt(data), self.hash(data))
        
    def calculate_intersection(self, id_incident, id_incident2, cluster_index = -1, cluster_index2 = -1):
        # delete the previous calculations
        self.cur.execute("DELETE FROM intersections WHERE id_incident = {0}".format(id_incident))
        self.db.commit()

        #if(cluster_index < 0):
        #    cluster_index = self.get_selected_cluster(id_incident)
        #if(cluster_index2 < 0):
        #    cluster_index2 = self.get_selected_cluster(id_incident2)

        ips = self.get_ips(id_incident, cluster_index)
        ips2 = self.get_ips(id_incident2, cluster_index2)

        total = len(set(ips).intersection(ips2))

        #update the table
        if(len(ips2) > 0) and (len(ips) > 0):
            sql = """INSERT INTO intersections (`id`, `id_incident`, `id_incident2`, `total`, 
            `intersection`, `intersection2`) VALUES ({},{},{},{},{},{})""".format(0,
            id_incident, id_incident2, total, total*100.0/len(ips), total*100.0/len(ips2))

            self.cur.execute(sql)
            self.db.commit()
        return 

    def calculate_all_intersections(self, id_incident):
        self.cur.execute("select * from incidents where id != {}".format(id_incident))
        for incident in self.cur.fetchall():
            self.calculate_intersection(id_incident, incident["id"])

    def save_clustering(self, sessions, clusters):
        for session, cluster in zip(sessions, clusters):
            self.cur.execute("update sessions set cluster_index={} WHERE id = {}".format(cluster,session["id"]))
        self.db.commit()

    def save_clustering2(self, sessions, clusters):
        for session, cluster in zip(sessions, clusters):
            self.cur.execute("update sessions set cluster_index2={} WHERE id = {}".format(cluster,session["id"]))
        self.db.commit()

    def save_selected_cluster(self, id_incident, selected_cluster):
        self.cur.execute("update incidents set cluster_index={} WHERE id = {}".format(selected_cluster,id_incident))
        self.db.commit()

    def clear_attack(self, id_incident):
    	self.cur.execute("update sessions set attack=0 WHERE id_incident = {}".format(id_incident))

    def label_attack(self, id_incident, attack_number, selected_clusters, selected_clusters2=[]):
    	for cluster in selected_clusters:
    		if len(selected_clusters2) > 0 :
    			for cluster2 in selected_clusters2:
    				self.cur.execute("update sessions set attack={} WHERE id_incident = {} and cluster_index={} and cluster_index2={}".format(
    					attack_number, id_incident, cluster, cluster2))
    		else:
    			self.cur.execute("update sessions set attack={} WHERE id_incident = {} and cluster_index={}".format(attack_number,
    				id_incident, cluster))
        self.db.commit()

    def incidents_summary(self, id_incidents) :
        for id in id_incidents:

            self.cur.execute("SELECT COUNT(DISTINCT IP) AS Count FROM sessions  WHERE id_incident = {}".format(id))
            num_ips = self.cur.fetchall()[0]['Count']
            self.cur.execute("SELECT COUNT(DISTINCT IP) AS Count FROM sessions  WHERE id_incident = {} and attack > 0".format(id))
            num_bots = self.cur.fetchall()[0]['Count']
            #pdb.set_trace()
            print "Incident {}, num IPs = {}, num Bots = {}".format(id, num_ips, num_bots)

    def extract_attack_ips_per_incident(self, id_incidents, attack_id = 0) :
        """
        stores the ips of the attackers in a file

        INPUT:: 
        id_incidents:  a list of incidents
        attack_id: the id of attack whose ips needs to be printed, if not specified then 
                   stores all attackers
        """
        for id in id_incidents:
            f1=open("ips_incident_{}_{}".format(id, attack_id), 'w+')
            sql_string = "SELECT DISTINCT IP_ENCRYPTED, IP_IV, IP_TAG FROM sessions  WHERE id_incident = {} and attack ".format(id)
            sql_string += (attack_id != 0) and " = {}".format(attack_id) or " > 0"
            self.cur.execute(sql_string)
            for elem in self.cur.fetchall():
            	ip = self.decrypt(elem['IP_ENCRYPTED'], elem['IP_IV'],  elem['IP_TAG'])
            	print >> f1, ip

            f1.close()
            
    def get_attack_ips_decrypted(self, id_incidents, id_attack = 0):

        sql_where = " where id_incident in ("
        for id in id_incidents:
            sql_where = sql_where + "{},".format(id)
        sql_where = sql_where[:-1]
        sql_where += ") "

        sql = "select IP_ENCRYPTED, IP_IV, IP_TAG from sessions " + sql_where
        if id_attack > 0:
            sql += " and attack = {}".format(id_attack) + " group by IP_ENCRYPTED"
        else:
            sql += " and attack > 0 " + " group by IP_ENCRYPTED"

        self.cur.execute(sql)
        ips = [self.decrypt(elem['IP_ENCRYPTED'], elem['IP_IV'],  elem['IP_TAG']) for elem in self.cur.fetchall()]
        ips = set(ips)
        return ips

    def extract_attack_ips(self, id_incidents) :
        """
        stores the ips of the attackers in a file

        INPUT:: 
        id_incidents:  a list of incidents
        """

        attacks = self.get_attack_ids(id_incidents)

        for attack in attacks:
            if attack <= 0 :
                continue
            ips = self.get_attack_ips_decrypted(id_incidents, attack)
            f1=open("ips_botnet_{}.txt".format(attack), 'w+')

            for ip in ips:
                print >> f1, ip

            f1.close()

    
    def calculate_common_ips(self, incidents1, id_attack,  incidents2):

        print "Intersection with incidents:"
        print incidents2
        attacks  = []
        if(id_attack > 0):
            attacks.append(id_attack)
        else:
            attacks = self.get_attack_ids(incidents1)

        for a in attacks:
            print "\n========================== Attack {}:".format(a)
            ips1 = self.get_attack_ips(incidents1, a)
            ips1 = set(ips1)
            print "Num IPs in the attack {}:".format(len(ips1))
            cross_table = []
            for i in incidents2:
               ips2 = set(self.get_attack_ips([i]))
               #ips2 = set(self.bothound_tools.get_banned_ips([i]))
               num = len(ips1.intersection(ips2))
               cross_table.append((i, len(ips1), len(ips2), num, num * 100.0 / min(len(ips1), len(ips2)) if min(len(ips1), len(ips2)) > 0 else 0))

            sorted_cross_table = sorted(cross_table, key=lambda k: k[4], reverse=True) 
            for d in sorted_cross_table:
                print "\n__________ Incident {}:".format(d[0])
                print "Num IPs in the incident {}:".format(d[2])
                print "# identical   IPs: {}".format(d[3])
                print "% of attack   IPs: {:.2f}%".format(100.0*d[3]/d[1])
                print "% of incident IPs: {:.2f}%".format(100.0*d[3]/d[2])

    def calculate_distances(self, id_incident, id_attack, id_incidents, features = [], cluster_indexes1 = -1, cluster_indexes2 = -1):

        if len(features) == 0:
            features = [
                "request_interval", #Feature Index 1
                "ua_change_rate", #Feature Index 2
                "html2image_ratio", #Feature Index 3
                "variance_request_interval", #Feature Index 4
                "payload_average", #Feature Index 5
                "error_rate", #Feature Index 6
                "request_depth", #Feature Index 7
                "request_depth_std", #Feature Index 8
                "session_length", #Feature Index 9
                "percentage_cons_requests" #Feature Index 10
            ]

        print "#######################  Distance calculator"
        print "Target indicent = ", id_incident
        print "Target attack = ", id_attack
        print "Target cluster index  1 = ", cluster_indexes1
        print "Target cluster index  2 = ", cluster_indexes2
        print "Incidents = ", id_incidents
        print "Features = ", features

        # get the target cluster
        sessions = self.get_sessions_atack(id_incident)
        X_target = []
        for s in sessions:
            if(id_attack > 0):
                if s["attack"] != id_attack:
                    continue
            else:
                if(s["cluster_index"] in cluster_indexes1):
                    continue
                if(len(cluster_indexes2) > 0 and s["cluster_index2"] in cluster_indexes2):
                    continue;
            row = []
            for f in features:
                row.append(s[f])
            X_target.append(row)
        X_target = np.array(X_target)

        if(X_target.shape[0]==0):
            print "Target attack is empty. Check id_incident and id_attack"
            return
        incidents = []

        #X_for_normalization = X_target
        X_for_normalization=np.empty([0,len(features)])

        for id_incident in id_incidents:
            incident = {"id" : id_incident}
            sessions = self.get_sessions_atack(id_incident)
            if(len(sessions) == 0):
                continue
            X = []
            attacks = []
            for s in sessions:
                row = []
                for f in features:
                    row.append(s[f])
                X.append(row)
                attacks.append(s["attack"])
            X = np.array(X)
            attacks = np.array(attacks)
            attack_indexes = np.unique(attacks)
            incident["attacks"] = []
            for attack_index in attack_indexes:
                attack = {"index" : attack_index}
                attack["X"] = X[attacks == attack_index]
                incident["attacks"].append(attack)

            X_for_normalization = np.concatenate((X_for_normalization, X), axis=0)

            incidents.append(incident)

        # normalization 
        std_scale = preprocessing.StandardScaler().fit(X_for_normalization)
        X_target = std_scale.transform(X_target)

        averages_target = np.average(X_target, axis=0)
        variances_target = np.var(X_target, axis=0)

        distances = []
        for incident in incidents:
            #print "_____________ Incident {}:".format(incident["id"])

            for attack in incident["attacks"]:
                d = {"incident" : incident["id"]}
                d["attack"] = attack["index"]

                attack["X"] = std_scale.transform(attack["X"])
                averages = np.average(attack["X"], axis=0)
                variances = np.var(attack["X"], axis=0)
                #pdb.set_trace()
                distance = 0.0
                for i in range(0,len(features)):
                    inc = np.square(averages_target[i] - averages[i])
                    if(inc != 0.0):
                        #print features[i]
                        #print averages_target[i],  averages[i]
                        #print variances_target[i],variances[i]
                        if(variances_target[i] * variances[i] == 0):
                            inc = sys.float_info.max
                        else:
                            inc /= np.sqrt(variances_target[i] * variances[i])

                    #print inc
                    #pdb.set_trace()
                        distance = distance + inc
                d["distance"] = distance 
                distances.append(d)           
                #print attack_index, "Distance = {}".format(distance)

        sorted_distances = sorted(distances, key=lambda x: x["distance"], reverse=True) 

        for d in sorted_distances:
            print d

    def get_attack_ids(self, id_incidents):

        sql = "select distinctrow attack from sessions  "
        sql_where = "where id_incident in ("
        for id in id_incidents:
            sql_where = sql_where + "{},".format(id)
        sql_where = sql_where[:-1]
        sql_where += ")"

        self.cur.execute(sql + sql_where + " and attack > 0")
        res = [elem["attack"] for elem in self.cur.fetchall()]
        res = sorted(res, key=lambda x: x, reverse=False) 
        return res

    def get_attacks(self, id_incidents):

        sql = "select distinctrow attack from sessions  "
        sql_where = "where id_incident in ("
        for id in id_incidents:
            sql_where = sql_where + "{},".format(id)
        sql_where = sql_where[:-1]
        sql_where += ")"

        attacks = self.get_attack_ids(id_incidents)
        res = []
        for elem in attacks:
            attack = {"id" : elem}
            if attack["id"] <= 0 :
                continue
            s1 = "select count(distinctrow IP) as count from sessions " + sql_where + " and attack ={}".format(elem)
            #pdb.set_trace()
            self.cur.execute(s1)
            attack["count"] = self.cur.fetchall()[0]['count']
            res.append(attack)

        res = sorted(res, key=lambda k: k["id"], reverse=False) 
        return res

    def calculate_attack_metrics(self, id_incidents):
        attacks = self.get_attack_ids(id_incidents)
        for attack in attacks:
            print "\n__________ Botnet {}:".format(attack)
            self.cur.execute("select AVG(session_length) as v from sessions where attack = %s", attack)
            print "Session length =", self.cur.fetchall()[0]['v'], "sec"

            self.cur.execute("select AVG(html2image_ratio) as v from sessions where attack = %s", attack)
            print "Html/image ratio =", self.cur.fetchall()[0]['v']

            self.cur.execute("select AVG(payload_average) as v from sessions where attack = %s", attack)
            print "Payload average =", self.cur.fetchall()[0]['v']

            self.cur.execute("select AVG(request_interval) as v from sessions where attack = %s", attack)
            v = self.cur.fetchall()[0]['v']
            print "Hit rate =", 60.0/v if v > 0 else 100, "/minute"
    
    
    def get_countries_count(self, id_incidents, attack):
        sql_where = "where id_incident in ("
        for id in id_incidents:
            sql_where = sql_where + "{},".format(id)
        sql_where = sql_where[:-1]
        sql_where += ")"
        
        if(attack > 0):
            sql_where += " and attack = {}".format(attack)
        else:
            sql_where += " and attack > 0"
        print sql_where
            

        self.cur.execute("select distinctrow IP, id_country from sessions " + sql_where)
        countries = self.cur.fetchall()
        res_dict = {}
        for c in countries:
            id = c["id_country"]
            if id in res_dict:
                res_dict[id] += 1
            else:
                res_dict[id] = 1
        res = []
        for key, value in res_dict.iteritems():
            temp = [key,value]
            res.append(temp)
        
        res = sorted(res, key=lambda x: x[1], reverse=True) 
        return res

    def get_top_attack_countries(self, id_incidents, max_countries = 5):
        countries = self.get_countries()
        names = {}
        for c in countries:
            names[c["id"]] = c["name"]
    
        attacks = self.get_attack_ids(id_incidents)

        for attack in attacks:
            cur_countries = self.get_countries_count(id_incidents, attack)
            n = max_countries if max_countries < len(cur_countries) else len(cur_countries)
            print "------ botnet", attack
            for i in range(0,n):
                print names[cur_countries[i][0]], cur_countries[i][1]

    def add_incident(self, start_date, target_host, duration_in_minutes = 60,  process = 1, comment = "") :

        stop_date = start_date + datetime.timedelta(minutes=duration_in_minutes)

        sql = "INSERT INTO incidents (start,stop,process,target,comment) VALUES (%s, %s, %s, %s, %s)"
        self.db.ping()
        self.cur.execute(sql,[start_date, stop_date, process, target_host, comment]) 
        self.db.commit()


    def __init__(self, conf):
        #we would like people to able to use the tool object even
        #if they don't have a db so we have no reason to load this
        #config in the constructor
        self.load_database_config(conf["database"], conf["elastic_db"])
