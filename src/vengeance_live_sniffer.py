"""
VengeanceLiveSniffer

This is a sniffer, when ever it receive a new record it adds it to the 
feature db. When it receives a signale from GreyMemory then it get a 
chunck from n min ago till now and uses unsupervised classification. 
To classify the botnet

AUTHORS: vmon, ludost (C) Equalit.ie Nov 2015: Initial version

"""
import logging

#Learn to ban modules
from features.src import *
from ip_sieve import IPSieve, ATSRecord
from logfetcher import LogFetcher

from collections import OrderedDict

# Gets the instance of the logger.
logging = logging.getLogger("fail2ban.filter")

class VengeanceLiveSniffer(LogFetcher):
    """
    listen to the log, if it gets message from
    GreyMemory then goes into classify mode for m minute and tries
    to clusterify after each log (for now) till greymemory says
    normal
    """

    pre_anomaly_history = 10 * 60 #seconds
    MAX_LOG_DB_SIZE = 1000000 #maximum number of ats record in memory
    
    def __init__(self):
        """
        Calls the parent constructor then initializes a ip_dictionary
        """
        super(VengeanceLiveSniffer, self).__init__()
        self._ip_log_db = OrderedDict()
        self._log_rec_counter = 0
        
    def process_incoming_logs(self, message):
        action message[0]

        if (action = BOTBANGER_LOG):
            return process_botbanger_log(message[1:])
        else if (action = GREYMEMORY_INFO):
            return process_greymemory_info(message[1:])

    def _process_botbanger_log(self, message):
        ipaddress = message[0]

        ipaddress = ipaddress.strip()
        ipmatch = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        if not ipmatch.match(ipaddress):
            logging.error("Failed to validate IP address %s - rejecting",
                              ipaddress)
            return False

        logging.debug("Received log for ip = %s", message[1])
        logging.debug("log is: %s", message)

        cur_log_rec = {}
        cur_log_rec["host"] = message[1]
        cur_log_rec["time"] = message[2]
        cur_log_rec["request"] = message[3]
        cur_log_rec["type"] = message[4]
        cur_log_rec["status"] = message[5]
        cur_log_rec["size"] = (not message[6]) and '0' or message[6]
        cur_log_rec["agent"] = message[7]
        cur_log_rec["hit"] = message[8]

        _gather_all_features(cur_log_rec)

    def _process_grey_memory_info(self, message):
        """
        Follow the github
        """

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

        cur_ip = cur_rec_dict["host"]
        cur_ats_rec = ATSRecord(cur_rec_dict)
        if not cur_ip in self._ip_log_db:
            self._ip_log_db[cur_ip] = [cur_ats_rec]
        else:
            #get rid of old session
            if cur_ats_rec.time_to_second() - self._ip_log_db[cur_ip][-1].time_to_second() > self._ip_sieve.DEAD_SESSION_PAUSE:
                self._log_rec_counter -= (len(self._ip_log_db[cur_ip]) - 1)
                self._ip_log_db[cur_ip] = []

            self._ip_log_db[cur_ip].append(cur_ats_rec)
        
        self._ip_sieve.set_pre_seived_order_records(dict(((cur_ip, self._ip_log_db[cur_ip]),)))
        
        ip_feature_db = {}
        for cur_feature_name in self._feature_list:
            cur_feature_tester = self._available_features[cur_feature_name](self._ip_sieve, ip_feature_db)
            cur_feature_tester.compute()

        print ip_feature_db
        return ip_feature_db

    def is_this_a_bot(self, cur_rec_dict):
        """
        Gets an ATS record and add the rec to the log database. Then re-compute the
        features and call the classifier to rejudge the ip.

        INPUT:
            ats_record: the record of the new request to ats
        
        """
        return len(self._predict_failure(self._gather_all_features(cur_rec_dict))) > 0