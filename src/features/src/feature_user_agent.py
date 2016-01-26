"""
Parse user agent string and create the appropriate features

AUTHORS::
    
    - Anton Mazhurin : 

notes: consider using https://github.com/woothee/woothee
"""
from learn2ban_feature import Learn2BanFeature
from ua_parser import user_agent_parser

class FeatureUserAgent(Learn2BanFeature):
    def __init__(self, ip_recs, ip_feature_db):
        Learn2BanFeature.__init__(self, ip_recs, ip_feature_db)
        
        #Each feature need to have unique index as the field number
        #in ip_feature_db
        self._FEATURE_INDEX = 11

    def string_kernel(self, string_value):
        value = 55
        return value

    def compute(self):
        """
        """
        ip_recs = self._ip_recs

        for cur_ip_rec in ip_recs:
            sample_size = len(ip_recs[cur_ip_rec])
            if sample_size < 1:
                self.append_feature(cur_ip_rec, 0)
                return

            # take the first record
            record = ip_recs[cur_ip_rec][0]

            # parsing the string
            parsed = user_agent_parser.Parse(record.agent)
            #print parsed['device']['family'] 
            #print parsed['os']['family']
            #print parsed['user_agent']['family']
            #print '-'
            
            feature_value  = self.string_kernel(record.agent)

            self.append_feature(cur_ip_rec, feature_value)










