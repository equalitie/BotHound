"""
Use IP to get location features

AUTHORS::
    
    - Mohiul Islam : 

"""
from learn2ban_feature import Learn2BanFeature
from geoip import geolite2
import math

class FeatureGEO(Learn2BanFeature):
    def __init__(self, ip_recs, ip_feature_db):
        Learn2BanFeature.__init__(self, ip_recs, ip_feature_db)
        
        #Each feature need to have unique index as the field number
        #in ip_feature_db
        # The following 3 features will be added: x, y, z
        # The indexes are 12, 13, 14
        self._FEATURE_INDEX = 12 # 13, 14 

    
    """
    This method requires installation of the following packages.
    It downloads the entire geo-location database, so its accessible offline. 
    pip install python-geoip
    pip install python-geoip-geolite2
    """
    @staticmethod
    def find_location(ip):
        match = {}
        match['country'] = ''
        match['latitude'] = 0
        match['longitude'] = 0
        try:
            v = geolite2.lookup(ip)
            if(v is not None):
                match['country'] = v.country
                match['latitude'] = v.location[0]
                match['longitude'] = v.location[1]
            else:
                match['country'] = ""
                match['latitude'] = 0
                match['longitude'] = 0

        except ValueError:
            pass
        return match

    """
    Latitude and longitude are polar coordinates
    So to use them as features in KMneas it is recommended to convert them into 
    Cartesian coordinates, so that Euclidean distance between two points makes sense. 
    """
    @staticmethod
    def convert_to_cartesian(location):
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

    def compute(self):
        """
        """
        ip_recs = self._ip_recs

        for cur_ip_rec in ip_recs:
            recs = ip_recs[cur_ip_rec]
            sample_size = len(recs)
            if sample_size < 1:
                self.append_feature(cur_ip_rec, 0)
                return

            for ats in ip_recs[cur_ip_rec]:
                payload = ats.payload
                # skip if ats record already has geo info
                if("location" in payload):
                    self._FEATURE_INDEX = 12            
                    self.append_feature(cur_ip_rec, payload['location'][0])
                    self._FEATURE_INDEX = 13
                    self.append_feature(cur_ip_rec, payload['location'][1])
                    self._FEATURE_INDEX = 14
                    self.append_feature(cur_ip_rec, payload['country_code'])
                else:
                    match = FeatureGEO.find_location(cur_ip_rec[0]);
                    self._FEATURE_INDEX = 12            
                    self.append_feature(cur_ip_rec, match['latitude'])
                    self._FEATURE_INDEX = 13
                    self.append_feature(cur_ip_rec, match['longitude'])
                    self._FEATURE_INDEX = 14
                    self.append_feature(cur_ip_rec, match['country'])
                break

            self._FEATURE_INDEX = 12
            


