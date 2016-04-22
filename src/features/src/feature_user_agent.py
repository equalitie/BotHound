"""
Parse user agent string and create the appropriate features

AUTHORS::
    
    - Anton Mazhurin : 

notes: consider using https://github.com/woothee/woothee
"""
from learn2ban_feature import Learn2BanFeature
from ua_parser import user_agent_parser
import pdb
import json

class FeatureUserAgent(Learn2BanFeature):
    def __init__(self, ip_recs, ip_feature_db):
        Learn2BanFeature.__init__(self, ip_recs, ip_feature_db)
        
        #Each feature need to have unique index as the field number
        #in ip_feature_db
        self._FEATURE_INDEX = 16 

    def string_kernel(self, string_value):
        value = 55
        return value

    def compute(self):
        """
        """
        ip_recs = self._ip_recs

        for cur_ip_rec in ip_recs:
            user_agents = {}
            sample_size = len(ip_recs[cur_ip_rec])
            if sample_size < 1:
                self.append_feature(cur_ip_rec, 0)
                return

            for record in ip_recs[cur_ip_rec]:
                ua = record.agent
                if ua is None:
                    ua = ""
                else:
                    ua = ua.encode('ascii','ignore')
                if(record.agent in user_agents):
                    user_agents[ua]["count"] = user_agents[ua]["count"] + 1
                    continue
                user_agents[ua] = {"count" : 1}

            #ua_list = []
            #for key, value in user_agents.iteritems():
            #    ua_list.append([key,value])
            
            #sorted_agents = sorted(ua_list, key=lambda k: k[1], reverse=True) 
            #s = sorted_agents[0][0]
            #self.append_feature(cur_ip_rec, s.encode('ascii','ignore') if s is not None else "")

            # parsing the string
            #parsed = user_agent_parser.Parse(record.agent)
            #print parsed['device']['family'] 
            #print parsed['os']['family']
            #print parsed['user_agent']['family']
            #print '-'
            
            for key, value in user_agents.iteritems():
                if key is None:
                    continue
                parsed = user_agent_parser.Parse(key)
                value["device_family"] = parsed["device"]["family"]
                value["os_family"] = parsed["os"]["family"]
                value["os_major"] = parsed["os"]["major"]
                value["os_minor"] = parsed["os"]["minor"]   
                value["os_patch"] = parsed["os"]["patch"]
                value["os_patch_minor"] = parsed["os"]["patch_minor"]
                value["ua_family"] = parsed["user_agent"]["family"]
                value["ua_major"] = parsed["user_agent"]["major"]
                value["ua_minor"] = parsed["user_agent"]["minor"]
                value["ua_patch"] = parsed["user_agent"]["patch"]
                user_agents[key] = value

            self.append_feature(cur_ip_rec, user_agents)










