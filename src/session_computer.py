"""
Analyse efficacy of learn2ban SVM system

AUTHORS:

- Bill (bill@equalit.ie) 2013/02/09
- Vmon: July 2013: Change log status. Trying to return back to OOP model
        after learn2bantool reconstruction disaster
- Vmon: Nov 2013: store the experiment model along with the experminet
                  results

- Vmon: Jan 2016: Adopt the code to bothound
"""

from multiprocessing import Process
from os.path import dirname, abspath
import os
import sys
import yaml,pdb

try:
    src_dir = dirname(dirname(abspath(__file__)))
except NameError:
    #the best we can do to hope that we are in the test dir
    src_dir = dirname(getcwd())

sys.path.append(src_dir)

import numpy as np
import logging
import datetime
import calendar

#learn2ban classes:
from ip_sieve import IPSieve

#feature classes
from features.src.learn2ban_feature import Learn2BanFeature
from features.src.feature_average_request_interval import FeatureAverageRequestInterval
from features.src.feature_cycling_user_agent import FeatureCyclingUserAgent
from features.src.feature_html_to_image_ratio import FeatureHtmlToImageRatio
from features.src.feature_HTTP_response_code_rate import FeatureHTTPResponseCodeRate
from features.src.feature_geo import FeatureGEO
from features.src.feature_payload_size_average import FeaturePayloadSizeAverage
from features.src.feature_percentage_consecutive_requests import FeaturePercentageConsecutiveRequests
from features.src.feature_request_depth import FeatureRequestDepth
from features.src.feature_request_depth_std import FeatureRequestDepthStd
from features.src.feature_session_length import FeatureSessionLength
from features.src.feature_user_agent import FeatureUserAgent
from features.src.feature_variance_request_interval import FeatureVarianceRequestInterval

#train to ban and other tools
from training_set import TrainingSet

from util.es_handler import ESHandler

from bothound_tools import BothoundTools

nb_training = 10
training_portions = [x / float(nb_training) for x in range(1, nb_training)]

class SessionExtractor():
    """
    This class read the db for the time of the attack from the database
    and compute the sessions for the chosen incidents
    """
    def __init__(self, bothound_tools):
        """
        store the exp config in self's attribute.
        """
        utc_datetime = datetime.datetime.utcnow()
        self.bothound_tools = bothound_tools
        self.es_handler = ESHandler(self.bothound_tools.es_user, self.bothound_tools.es_password,
            bothound_tools.es_host, self.bothound_tools.es_port)

    def process_incident(self, incident):
        """
        get the incident time from the db and gathers all features

        INPUT:
            log_files: the logs that we went through it.
        """
        if(incident is None):
            return 

        #start = 1451560001000
        #stop =  1451560001000

        # get the logs from ES
        banned_ips = self.es_handler.get_banjax(incident['start'], incident['stop'], incident['target'])
        #banned_ips = []

        # get the logs from ES
        ats_records = self.es_handler.get(incident['start'], incident['stop'], incident['target'])

        # calculate IP dictionary with ATS records
        ip_sieve = IPSieve()
        ip_records = ip_sieve.process_ats_records(ats_records)

        # calculate features
        ip_feature_db = {}

        #At this stage it is only a peliminary list we might lose features
        #due to 0 variance
        self._active_feature_list = []
        #do a dry run on all features just to gather the indeces of all available
        #features
        for CurentFeature in Learn2BanFeature.__subclasses__():
            f = CurentFeature(ip_records, ip_feature_db)
            self._active_feature_list.append(f._FEATURE_INDEX)

        for CurentFeature in Learn2BanFeature.__subclasses__():
            f = CurentFeature(ip_records, ip_feature_db)
            #logging.info("Computing feature %i..."% f._FEATURE_INDEX)
            print "Computing feature %i..."% f._FEATURE_INDEX
            f.compute()

        # post process the features
        ip_feature_db = self.bothound_tools.post_process(ip_feature_db)

        # delete the old sessions for thie incidend
        self.bothound_tools.delete_sessions(incident['id'])

        #print ip_feature_db
        self.bothound_tools.add_sessions(incident['id'], ip_feature_db, banned_ips)
        self.bothound_tools.set_incident_process(incident['id'], False)
        print "Incident {} processed.".format(incident['id'])
        return ip_feature_db

    def extract(self):
        """
        check all incidents which needs to be processed and compute the features on them
        finally store the sessions in the db
        """
        #this make more sense to happens in the constructor however,
        for incident in bothound_tools.get_incidents(process = True):
            cur_session_feature_db = self.process_incident(incident)
        

    def store_results(self, session_feature_db):
        # Add the result to the database
        for cur_sesion in session_feature_db:
            db_tools.store(cur_session)

    def calculate_cross_table(self, incidents):
        # Calculating common Banned Ips for a set of incidents
        es_handler = ESHandler(self.bothound_tools.es_user, self.bothound_tools.es_password,
                self.bothound_tools.es_host, self.bothound_tools.es_port)
        common = -1
        print "processing..."
        result = []
        groups = []
        for i in incidents:
            incident = self.bothound_tools.get_incident(i)[0]
            #pdb.set_trace()
            banned_ips = es_handler.get_banjax(incident['start'], incident['stop'], incident['target'])
            ips = []
            for p in banned_ips.keys():
                ips.append(p)
            if(common<0):
                common = set(ips)
            else:
                common = common.intersection(ips)

            result.append([len(ips), len(common)])
            groups.append(ips)
            
        for i in range(0, len(groups)):
            print "Incident", i, len(groups[i])

        ip_counts = {}
        for g in groups:
            for ip in g:
                if(ip in ip_counts):
                    ip_counts[ip] = ip_counts[ip] + 1
                else:
                    ip_counts[ip] = 1

        for i in range(1, len(incidents)+1):
            cur_count = 0
            for ip in ip_counts:
                if(ip_counts[ip] == i):
                    cur_count = cur_count + 1
            print cur_count, i

        """
        #calculate moving intersection
        print "moving intersection"
        for i in range(0, len(incidents)-1):
            ips1 = set(groups[i])
            ips2 = set(groups[i+1])
            print i+1, i+2, len(ips1.intersection(ips2))
        """

        print "cross table"
        cross_table = []
        for i in range(0, len(incidents)-1):
            for j in range(i+1, len(incidents)-1):
               ips1 = set(groups[i])
               ips2 = set(groups[j])
               num = len(ips1.intersection(ips2))
               cross_table.append((i+1, j+1, len(ips1), len(ips2), num, num * 100.0 / min(len(ips1), len(ips2))))

        sorted_cross_table = sorted(cross_table, key=lambda k: k[5], reverse=True) 
        f1=open('cross_table.txt', 'w+')
        for d in sorted_cross_table:
            s = "{},{},{},{},{},{:.1f}%".format(d[0], d[1], d[2], d[3], d[4], d[5])
            print s
            print >> f1, s
        f1.close()

    def calculate_sizes(self, incidents):
        es_handler = ESHandler(self.bothound_tools.es_user, self.bothound_tools.es_password,
                self.bothound_tools.es_host, self.bothound_tools.es_port)

        ips = []
        for i in incidents:
            incident = self.bothound_tools.get_incident(i)[0]
            cur_ips = es_handler.get_deflect_unique_ips(incident['start'], incident['stop'], incident['target'])
            ips.append(set(cur_ips.keys()))

        for i in range(0, len(ips)):
            print i, "Num unique IPs:",  len(ips[i])

    def calculate_urls(self, incidents):
        es_handler = ESHandler(self.bothound_tools.es_user, self.bothound_tools.es_password,
                self.bothound_tools.es_host, self.bothound_tools.es_port)
        incident_urls = []
        for i in incidents:
            incident = self.bothound_tools.get_incident(i)[0]
            urls = es_handler.get_banned_url_count(incident['start'], incident['stop'], incident['target'])

            urls_list = []
            for key, value in urls.iteritems():
                temp = [key,value]
                urls_list.append(temp)

            urls_sorted = sorted(urls_list, key=lambda k: k[1], reverse=True) 
            num_most = len(urls_sorted) if len(urls_sorted) < 3 else 3

            incident_urls.append(urls_sorted[0:num_most])

        for urls in incident_urls:
            print "incident", i
            for url in urls:
                print url[1], url[0]
            



if __name__ == "__main__":

    stram = open("../conf/bothound.yaml", "r")
    conf = yaml.load(stram)

    bothound_tools = BothoundTools(conf)
    bothound_tools.connect_to_db()

    session_extractor = SessionExtractor(bothound_tools)

    #session_extractor.extract()

    incidents = [24,25,26,19,27]
    #id_incidents = [29,30,31,32,33,34]


    #session_extractor.calculate_cross_table(id_incidents)
    
    #session_extractor.calculate_sizes(id_incidents)

    urls = session_extractor.calculate_urls(incidents)
    

