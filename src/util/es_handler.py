# This is a Python query script that reads and prints ES records on the l2b server

from elasticsearch import Elasticsearch
import certifi
import datetime
import calendar

class ESHandler:
    def __init__(self, es_user, es_password, es_host, es_port):
        """
        Get the credential and makes the elastic search object for later
        queries
        """
        self.es = Elasticsearch(
            [es_host],        # name of node to be added here 'http(s)://user:password@server:port']
            http_auth=(es_user, es_password),
            port= es_port, #add the port number,
            use_ssl=True,
            verify_certs=True,
            ca_certs=certifi.where())

    def get_logs(self, start, stop):
        """
        Get deflect log from es
        """
        ts_start = 1000*calendar.timegm(start.timetuple())
        ts_stop = 1000*calendar.timegm(stop.timetuple())

        cur_index = start.strftime('deflect.log-%Y.%m.%d')

        return self.es.search(index=cur_index, body =
            #add index between the quotation marks
            {
            "from" : 0, "size" : 10000,
            #the size can be changed but apparently the current query does not show > 10000 results.
            "query": {
            "bool": {
            "must": { "match_all": {} },
            "filter": {
                "range": {
                "@timestamp": {
                    "gte": ts_start,
                    "lte": ts_stop,
            #timestamps are for start/end date in epoch format. this format should be changed for other dates (current one is for 31.12.2015)
            "format": "epoch_millis"
                   #format could be changed, but for now keeping the epoch + millisecond one
              }
            }
          }
        }
      }
    })

#print len(query_result(0,0,0))
#print query_deflect_logs(0,0,0)
