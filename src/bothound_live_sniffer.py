"""
BothoundLiveSniffer

This is a sniffer, when ever it receive a new record it adds it to the 
feature db. When it receives a signal from GreyMemory then it get a 
chunk from n min ago till now and uses unsupervised classification. 
To classify the botnet

AUTHORS: vmon, ludost (C) Equalit.ie Nov 2015: Initial version

"""
import logging
import numpy as np
import re
import sklearn
import pdb 
import json

#Learn to ban modules
from features.src.learn2ban_feature import Learn2BanFeature
from features.src.feature_average_request_interval import FeatureAverageRequestInterval
from features.src.feature_cycling_user_agent import FeatureCyclingUserAgent
from features.src.feature_html_to_image_ratio import FeatureHtmlToImageRatio
from features.src.feature_HTTP_response_code_rate import FeatureHTTPResponseCodeRate
from features.src.feature_payload_size_average import FeaturePayloadSizeAverage
from features.src.feature_percentage_consecutive_requests import FeaturePercentageConsecutiveRequests
from features.src.feature_request_depth import FeatureRequestDepth
from features.src.feature_request_depth_std import FeatureRequestDepthStd
from features.src.feature_session_length import FeatureSessionLength
from features.src.feature_user_agent import FeatureUserAgent
from features.src.feature_variance_request_interval import FeatureVarianceRequestInterval
from features.src.feature_geo import FeatureGEO
from util.ats_record import ATSRecord
from logfetcher import LogFetcher

from collections import OrderedDict
import datetime
import calendar

# Gets the instance of the logger.
logging = logging.getLogger("fail2ban.filter")

class BothoundLiveSniffer(LogFetcher):
    """
    listen to the log, if it gets message from
    GreyMemory then goes into classify mode for m minute and tries
    to clusterify after each log (for now) till greymemory says
    normal
    """
    pre_anomaly_history = 10 * 60 #seconds
    MAX_LOG_DB_SIZE = 1000000 #maximum number of ats record in memory
    DEAD_SESSION_PAUSE = 10*60*3 #minimum number of seconds between two session

    def __init__(self, conf_options, tools):
        self.tools = tools
        """
        Calls the parent constructor then initializes a ip_dictionary
        """
        super(BothoundLiveSniffer, self).__init__(conf_options)
        self._ip_log_db = OrderedDict()
        self.ip_row_tracker = {}
        self.ip_feature_array = np.array([])
        self._log_rec_counter = 0

        self._build_available_feature_list()
        
    def _build_available_feature_list(self):
        """
        Search all the available feature class and stored them
        in a dictionary indexed by their names
        """
        self._available_features={}
        self._feature_list = list()
        for CurrentFeatureType in Learn2BanFeature.__subclasses__():
            self._available_features[CurrentFeatureType.__name__] = CurrentFeatureType
            self._feature_list.append(CurrentFeatureType.__name__)


    def process_received_message(self, action, message):
        #print action, message
        if (action == self.BOTBANGER_LOG):
            return self._process_botbanger_log(message)
        elif (action == self.GREYMEMORY_INFO):
            return self._process_greymemory_info(message)

    def _process_botbanger_log(self, message):
        try:
            decoded_message = message.split(',')
            #we need to decode them from b64

            for i in range(0, len(decoded_message)):
                decoded_message[i] = decoded_message[i].decode('base64')
        except:
            logging.error("Failed to decode the botbanger message")
            return False
        
        return self._process_decoded_message(decoded_message) 
    
    def _process_decoded_message(self, decoded_message):
        ipaddress = decoded_message[0]
            
        ipaddress = ipaddress.strip()
        ipmatch = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        if not ipmatch.match(ipaddress):
            logging.error("Failed to validate IP address %s - rejecting",
                              ipaddress)
            return False

        logging.debug("Received log for ip = %s", ipaddress)
        logging.debug("log is: %s", decoded_message)

        cur_log_rec = {}
        cur_log_rec["host"] = decoded_message[0]
        cur_log_rec["time"] = decoded_message[1]
        cur_log_rec["request"] = decoded_message[2]
        cur_log_rec["type"] = decoded_message[3]
        cur_log_rec["status"] = decoded_message[4]
        cur_log_rec["size"] = (not decoded_message[5]) and '0' or decoded_message[5]
        cur_log_rec["agent"] = decoded_message[6]
        cur_log_rec["hit"] = decoded_message[7]

        return self._clusterify(cur_log_rec)

    def _process_greymemory_info(self, message):
        #print message
        #print str(message)
        logging.debug("greymemory says " + "," + str(message))
        #print "greymemory says " + "," + str(message)

        try:
            decoded_message = json.loads(message)        
            if(decoded_message['message type'] == 'anomaly_started') :
                self._start_recording(decoded_message)
            elif(decoded_message['message type'] == 'anomaly_stopped') :
                self._stop_recording(decoded_message)

        except Exception,e:
            logging.error("Failed to decode the greymemory message")
            print e
            return False

        return True

    def _start_recording(self, message):
        #print "Creating incident"
        start_date = datetime.datetime.fromtimestamp(message["time_stamp"])
        print "New incident : " + message["target_host"] + ", " + start_date.strftime("%Y-%m-%d %H:%M:%S")
        if(message["target_host"] == "test_host"):
            return
        self.tools.add_incident(start_date, message["target_host"])

    def _stop_recording(self, message):        
        #print "_stop_recording"
        pass

    def _gather_all_features(self, cur_rec_dict):
        """
        Set the ip_sieve log equal to the cur ip's history and 
        compute features  from feature list for that ip only
        """
        #check for too much memory consumption
        if (self._log_rec_counter == self.MAX_LOG_DB_SIZE):
            oldest_rec = self._ip_log_db.popitem(last=False)
            self._log_rec_counter -= (len(oldest_rec[1]) -1)
        else:
            self._log_rec_counter += 1

        print "no of ips", len(self._ip_log_db), " no of log recs", self._log_rec_counter

        from random import randint
        cur_ip = cur_rec_dict["host"]
        #cur_ip = cur_ip[:-1] + str(randint(1,255))
        cur_ats_rec = ATSRecord(cur_rec_dict)
        if not cur_ip in self._ip_log_db:
            self._ip_log_db[cur_ip] = [cur_ats_rec]
        else:
            #get rid of old session
            if cur_ats_rec.time_to_second() - self._ip_log_db[cur_ip][-1].time_to_second() > self.DEAD_SESSION_PAUSE:
                self._log_rec_counter -= (len(self._ip_log_db[cur_ip]) - 1)
                self._ip_log_db[cur_ip] = []

            self._ip_log_db[cur_ip].append(cur_ats_rec)
            #get rid of ip's old row in the ip feature array
            np.delete(self.ip_feature_array, (self.ip_row_tracker[cur_ip]), axis=0)
        
        ip_recs = dict(((cur_ip, self._ip_log_db[cur_ip]),))

        #so this is stupid we should compute accumulatively
        #instead so ip_feature_db should be the member of
        #the class, it probably should be a training set
        ip_feature_db = {}
        for cur_feature_name in self._feature_list:
            cur_feature_tester = self._available_features[cur_feature_name](ip_recs, ip_feature_db)
            cur_feature_tester.compute()

        #turing ip_feature_db into a numpy array
        self.ip_row_tracker[cur_ip] = self.ip_feature_array.shape[0]
        cur_ip_row = [[ip_feature_db[ip][feature] for feature in range(1, len(self._feature_list)+1)] for ip in ip_feature_db]
        if (self.ip_feature_array.shape[0] == 0):
            self.ip_feature_array = np.array(cur_ip_row)
        else:
            self.ip_feature_array = np.vstack([self.ip_feature_array, cur_ip_row]) 

    def _clusterify(self, cur_rec_dict):
        """
        Gets an ATS record and add the rec to the log database. Then re-compute the
        features and call the classifier to rejudge the ip.

        INPUT:
            ats_record: the record of the new request to ats
        
        """
        from sklearn.cluster import KMeans

        #We need to turn ip_table to numpy array as it done in
        #train2ban and botsniffer using TrainingSet but for now
        #we go with the simple just hack solution
        
        self._gather_all_features(cur_rec_dict)

        for no_of_clusters in range(2,20):
            if (self.ip_feature_array.shape[0] >= no_of_clusters) :
                kmeans = KMeans(n_clusters=no_of_clusters)
                kmeans.fit(self.ip_feature_array)
                    
                j = [0]*no_of_clusters
                    
                for i in kmeans.predict(self.ip_feature_array): 
                    j[i] = j[i]+1

                logging.debug(",".join(map(str,j)))
        return True
