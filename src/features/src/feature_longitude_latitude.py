"""
Parse user agent string and create the appropriate features

AUTHORS::
    
    - Mohiul Islam : 

"""
from learn2ban_feature import Learn2BanFeature
from geoip import geolite2
import math

class FeatureLongitudeLatitude(Learn2BanFeature):
    def __init__(self, ip_recs, ip_feature_db):
        Learn2BanFeature.__init__(self, ip_recs, ip_feature_db)
        
        #Each feature need to have unique index as the field number
        #in ip_feature_db
        self._FEATURE_INDEX = 12

    """
    This method requires installation of the following packages.
    It downloads the entire geo-location database, so its accessible offline. 
    pip install python-geoip
    pip install python-geoip-geolite2
    """
    def find_location(self, ip):
        match = geolite2.lookup(ip)
        return match.location
    
    """
    Latitude and longitude are polar coordinates
    So to use them as features in KMneas it is recommended to convert them into 
    Cartesian coordinates, so that Euclidean distance between two points makes sense. 
    """
    def convert_to_cartesian(self, location):
        latitude = location[0]
        longitude = location[0]
        # Spherical coordinates in Radians
        longitude_rad = longitude * (2 * math.pi)/360
        latitude_rad = (latitude * 2) * (2 * math.pi)/360
        R = (6378 + 6356)/2
        
        # Cartesian coordinates
        cartesian = {};
        cartesian['x'] = R * math.cos(latitude_rad) * math.cos(longitude_rad)
        cartesian['y'] = R * math.cos(latitude_rad) * math.sin(longitude_rad)
        cartesian['z'] = R * math.sin(latitude_rad)
    
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
            
            location = self.find_location(record);
            cartesian = self.convert_to_cartesian(location);
            
            self.append_feature(cur_ip_rec, cartesian['x'])
            self.append_feature(cur_ip_rec, cartesian['y'])
            self.append_feature(cur_ip_rec, cartesian['z'])
            