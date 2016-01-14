"""
Use IP to get location features

AUTHORS::
    
    - Mohiul Islam : 

"""
from learn2ban_feature import Learn2BanFeature
from bothound_tools import BothoundTools

class FeatureLongitudeLatitudeX(Learn2BanFeature):
    def __init__(self, ip_recs, ip_feature_db):
        Learn2BanFeature.__init__(self, ip_recs, ip_feature_db)
        
        #Each feature need to have unique index as the field number
        #in ip_feature_db
        self._FEATURE_INDEX = 12

    
    def compute(self):
        """
        """
        ip_recs = self._ip_recs

        for cur_ip_rec in ip_recs:
            sample_size = len(ip_recs[cur_ip_rec])
            if sample_size < 1:
                self.append_feature(cur_ip_rec, 0)
                return
            
            location = BothoundTools.find_location(cur_ip_rec);
            cartesian = BothoundTools.convert_to_cartesian(location);
            
            self.append_feature(cur_ip_rec, cartesian['x'])
            