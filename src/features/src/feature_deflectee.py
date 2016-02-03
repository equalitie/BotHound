"""
Parse target domain name and create the appropriate features
AUTHORS::
    - Anton Mazhurin : 
"""
from learn2ban_feature import Learn2BanFeature
from ua_parser import user_agent_parser

class FeatureDeflectee(Learn2BanFeature):
    def __init__(self, ip_recs, ip_feature_db):
        Learn2BanFeature.__init__(self, ip_recs, ip_feature_db)
        
        #Each feature need to have unique index as the field number
        #in ip_feature_db
        self._FEATURE_INDEX = 15 

    def compute(self):
        if(self.deflectees is None):
            return

        ip_recs = self._ip_recs

        for cur_ip_rec in ip_recs:
            domain = ""
            for payload in ip_recs[cur_ip_rec]:
                # we tale the first one hoping the rest are the same
                domain = payload.get_target()
                break

            self.append_feature(cur_ip_rec, domain)










