# This is a Python query script that reads and prints ES records on the l2b server

from elasticsearch import Elasticsearch
import certifi
import datetime
import calendar
import json
import pdb

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

        #cur_index1 = start.strftime('deflect.log-%Y.%m.%d')
        #cur_index2 = stop.strftime('deflect.log-%Y.%m.%d')
        indexes = [start.strftime('deflect.log-%Y.%m.*')]
        if(start.month != stop.month):
            indexes.append(stop.strftime('deflect.log-%Y.%m.*'))

        page = self.es.search(index=indexes, 
            scroll = '5m',
            search_type = 'scan',
            size = 10000,
            body =
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
        result = json.loads("{}")
        sid = page['_scroll_id']
        page_index = 0
        scroll_size = page['hits']['total'] 
        print "scroll_size", scroll_size
        # Start scrolling
        pdb.set_trace()
        
        while (scroll_size > 0):
            print "Scrolling...", page_index
            page_index = page_index + 1
            page = es.scroll(scroll_id = sid, scroll = '5m')
            # Update the scroll ID
            sid = page['_scroll_id']
            # Get the number of results that we returned in the last scroll
            scroll_size = len(page['hits']['hits'])
            print "scroll size: " + str(scroll_size)
            # Do something with the obtained page
            json_result = page['hits']['hits']
            result.append(json_result)

        return result



#print len(query_result(0,0,0))
#print query_deflect_logs(0,0,0)
