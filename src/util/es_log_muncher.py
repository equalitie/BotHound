"""
Simply getting the relevant fields from es data and put them into
ats record
"""
UNREASANABLE_SIZE = 100*1024*1024 #100MB
NORMAL_HTTP_METHODS = ["-","GET", "HEAD", "POST"]
VALID_HTTP_METHODS = ["-","OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "VERSION-CONTROL", "REPORT", "CHECKOUT", "CHECKIN", "UNCHECKOUT", "MKWORKSPACE", "UPDATE", "LABEL", "MERGE", "BASELINE-CONTROL", "MKACTIVITY", "ORDERPATCH", "ACL"]

def parse_es_json_object(hit_json_object):

    res = hit_json_object["_source"]
    if "client_ip" not in res:
        return None
    ats_res = {}
    ats_res["host"] = res["client_ip"]

    ats_res["agent"] = None
    if "client_ua" in res:
        if res["client_ua"] == "-":
            ats_res["agent"] = None
        else:
            ats_res["agent"] = res["client_ua"]

    try:
        ats_res["status"] = int(res["http_response_code"])
    except ValueError, e:
        ats_res["status"] = 0
        print "invalid http_response_code %s"%(res["http_response_code"])
        print res


    ats_res["http_ver"] = res["http_request_version"]
    ats_res["method"] = res["client_request_method"]
    ats_res["request"] = res["client_url"]

    if ats_res["method"] not in VALID_HTTP_METHODS:
        print "ignoring request with invalid method %s"%(ats_res["method"])
        return None
    elif ats_res["method"] not in NORMAL_HTTP_METHODS:
        print "abnormal http request, somebody messing around?:", ats_res["method"]

    #the specific extension is only important in text/html otherwise
    #the general type gives us enough information
    doc_type = str(res["content_type"]).split('/')
    if len(doc_type) == 2:
        #check for non standard
        ats_res["type"] = str(doc_type[1]) if str(doc_type[1]) == 'html' else str(doc_type[0])
    else:
        #the doc type is not valid perhapse because the request has not been served
        #we guess the type from the request then
        ats_res["type"] = ats_res["request"].find('.', ats_res["request"].rfind('/')) == -1 and 'html' or ats_res["request"].split('.')[-1]

        #group all the images
        ats_res["type"] = res["type"] in ["jpg", "gif", "png"] and "image" or res["content_type"]

    #if (not res["type"] == 'html'): print res["type"], line

    if res["reply_length_bytes"] == "-":
        ats_res["size"] = 0
    else:
        ats_res["size"] = int(res["reply_length_bytes"])

    #just to observe the illogically large sizes
    if (ats_res["size"] >= UNREASANABLE_SIZE):
        print "unreasonably large payload "
        return None

    timestamp = res["@timestamp"]
    ats_res["time"] = timestamp[:timestamp.find('.000Z')] + "Z"
    ats_res["time_raw"] = timestamp

    if('geoip' in res):
        geoip = res['geoip']
        if('country_code2' in geoip):
            ats_res['country_code'] = geoip['country_code2']
        if('city_name' in geoip):
            ats_res['city'] = geoip['city_name']
        if('location' in geoip):
            ats_res['location'] = geoip['location']

    ats_res['client_request_host'] = res['client_request_host']

    return ats_res;

if __name__ == "__main__":
    for files in glob.glob("*.log"):
        for l in open(files,'rb'):
	    parse_line(l)
