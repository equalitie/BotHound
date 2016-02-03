# This is a Python query script that reads and prints ES records on the l2b server

from elasticsearch import Elasticsearch
import certifi
import datetime
import calendar

es = Elasticsearch(
    '[...]',
    # name of node to be added here 'http(s)://user:password@server:port']
    port= #add the port number,
    use_ssl=True,
    verify_certs=True,
    ca_certs=certifi.where()
)

def query_es_for_deflect_logs(interval, start, end):
    return es.search(index="", body =
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
               "gte": start,
               "lte": end,
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
print query_result(0,0,0)
