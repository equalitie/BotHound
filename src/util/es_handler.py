# This is a Python query script that reads and prints ES records on the l2b server

from elasticsearch import Elasticsearch
import certifi
import datetime
import calendar
import json
import pdb
from util.ats_record import ATSRecord
import util.es_log_muncher 
import datetime

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

    def get(self, start, stop, target):
        """
        Get deflect log from es
        """

        ts_start = 1000*calendar.timegm(start.timetuple())
        ts_stop = 1000*calendar.timegm(stop.timetuple())

        indexes = [start.strftime('deflect.log-%Y.%m.%d')]
        if(start.day != stop.day):
            indexes.append(stop.strftime('deflect.log-%Y.%m.%d'))
        
        
        #indexes = [start.strftime('deflect.log-%Y.%m.*')]
        #if(start.month != stop.month):
            #indexes.append(stop.strftime('deflect.log-%Y.%m.*'))
        print "es.search() start..."
        if (target is not None) :
            es_body = {
            "from" : 0, "size" : 10000,
            "sort" :[{"@timestamp":{"order":"asc"}}],
            #the size can be changed but apparentlay the current query does not show > 10000 results.
            "query": {
            "bool": {
            "should": [
                {"match": {
                  "client_request_host": { 
                    "query": "{}".format(target),
                    #"query": "www.kotsubynske.com.ua",
                    "type": "phrase"
                  }
                }},
                {"match": {
                  "client_request_host": { 
                    "query": "www.{}".format(target),
                    #"query": "kotsubynske.com.ua",
                    "type": "phrase"
                  }
                }}
            ], "minimum_should_match": 1,
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
    }
        else:
            es_body = {
            "from" : 0, "size" : 10000,
            "sort" :[{"@timestamp":{"order":"asc"}}],
            #the size can be changed but apparentlay the current query does not show > 10000 results.
            "query": {
            "bool": {
            #"must": { "match_all": {} },
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
    }
        """
        f1=open('./q.txt', 'w+')
        print es_body
        print >>f1, es_body
        print >>f1, indexes
        print >>f1, ts_start
        print >>f1, ts_stop
        pdb.set_trace()
        """ 
        result = []
        try: 
            #pdb.set_trace()
            page = self.es.search(index=indexes, 
                scroll = '5m',
                #search_type = 'scan',
                size = 10000,
                body = es_body
                #add index between the quotation marks
                )

            sid = page['_scroll_id']
            page_index = 0
            scroll_size = page['hits']['total'] 
            total_size = scroll_size
            print "total # of hits : ", total_size
            # Start scrolling

            num_processed = 0
            while (scroll_size > 0):
                print "Scrolling...", page_index
                # Do something with the obtained page
                json_result = page['hits']['hits']
                #pdb.set_trace()

                for log in json_result:
                    #print log['_source']['@timestamp']
                    cur_rec_dict = util.es_log_muncher.parse_es_json_object(log)
                    if cur_rec_dict:
                        cur_ats_rec = ATSRecord(cur_rec_dict);

                        '''
                        if("location" in cur_ats_rec.payload):
                            l = cur_ats_rec.payload['location']
                            country = cur_ats_rec.payload['country_code']
                            if(country == 'UA'):
                                print country, cur_ats_rec.agent
                                pdb.set_trace()
                        '''


                        #print cur_ats_rec.payload['time']
                        result.append(cur_ats_rec);
                        num_processed = num_processed +  1
                            
                print "num_processed: " + str(num_processed) + ", total (" + str(total_size) + ")"
                if(num_processed > 5000000):
                    break

                page_index = page_index + 1
                tStart = datetime.datetime.now()
                page = self.es.scroll(scroll_id = sid, scroll = '5m')
                print "scroll time ,sec:", (datetime.datetime.now() - tStart).total_seconds()

                # Update the scroll ID
                sid = page['_scroll_id']
                # Get the number of results that we returned in the last scroll
                scroll_size = len(page['hits']['hits'])
                #print "scroll size: " + str(scroll_size)
        except Exception as ex:
            print ex
 
        return result

    def get_banjax(self, start, stop, target):
        """
        Get banjax log from es
        """

        ts_start = 1000*calendar.timegm(start.timetuple())
        ts_stop = 1000*calendar.timegm(stop.timetuple())

        indexes = [start.strftime('banjax-%Y.%m.%d')]
        if(start.day != stop.day):
            indexes.append(stop.strftime('banjax-%Y.%m.%d'))
        
        
        #indexes = [start.strftime('deflect.log-%Y.%m.*')]
        #if(start.month != stop.month):
            #indexes.append(stop.strftime('deflect.log-%Y.%m.*'))
        print "es.search() start banjax..."
        if (target is not None) :
            es_body = {
            "from" : 0, "size" : 10000,
            "sort" :[{"@timestamp":{"order":"asc"}}],
            #the size can be changed but apparentlay the current query does not show > 10000 results.
            "query": {
            "bool": {
            "should": [
                {"match": {
                  "http_host": { 
                    "query": "{}".format(target),
                    #"query": "www.kotsubynske.com.ua",
                    "type": "phrase"
                  }
                }},
                {"match": {
                  "http_host": { 
                    "query": "www.{}".format(target),
                    #"query": "kotsubynske.com.ua",
                    "type": "phrase"
                  }
                }}
            ], "minimum_should_match": 1,
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
    }
        else:
            es_body = {
            "from" : 0, "size" : 10000,
            "sort" :[{"@timestamp":{"order":"asc"}}],
            #the size can be changed but apparentlay the current query does not show > 10000 results.
            "query": {
            "bool": {
            #"must": { "match_all": {} },
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
    }
        
        #f1=open('q.txt', 'w+')
        #s = json.dumps(es_body, indent = 4)
        #print >>f1, start, stop
        #print >>f1, indexes
        #print >>f1, s
        #f1.close()
           
        result = {}
        try:
            #pdb.set_trace()
            page = self.es.search(index=indexes, 
                scroll = '5m',
                #search_type = 'scan',
                size = 10000,
                body = es_body
                #add index between the quotation marks
                )
            #result = []
            sid = page['_scroll_id']
            page_index = 0
            total_size = page['hits']['total'] 
            print "total # of Banjax hits : ", total_size

            #f1=open('q.txt', 'a+')
            #print >> f1, "total # of Banjax hits : ", total_size
            #f1.close()
            #pdb.set_trace()

            # Start scrolling
            #pdb.set_trace()
            num_processed = 0
            scroll_size = total_size
            
            while (scroll_size > 0):
                print "Scrolling banjax...", page_index

                json_result = page['hits']['hits']
                for log in json_result:
                    src = log["_source"]
                    if "client_ip" not in src:
                        continue
                    v = {}
                    v['count'] = 1
                    if "rule_type" in src:
                        v['rule'] = src['rule_type']
                    
                    if(src['client_ip'] in result):
                        result[src['client_ip']]['count'] = result[src['client_ip']]['count'] + 1
                    else:
                        result[src['client_ip']] = v  

                print "num_processed: " + str(num_processed)
                if(num_processed > 5000000):
                    break

                page_index = page_index + 1
                tStart = datetime.datetime.now()
                page = self.es.scroll(scroll_id = sid, scroll = '2m')
                print "scroll time ,sec:", (datetime.datetime.now() - tStart).total_seconds()

                # Update the scroll ID
                sid = page['_scroll_id']
                # Get the number of results that we returned in the last scroll
                scroll_size = len(page['hits']['hits'])
                print "scroll size: " + str(scroll_size)
        except Exception as ex:
            print ex

        return result


#print len(query_result(0,0,0))
#print query_deflect_logs(0,0,0)
