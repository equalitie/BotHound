import pdb
import shlex

months = {
'Jan':'01',
'Feb':'02',
'Mar':'03',
'Apr':'04',
'May':'05',
'Jun':'06',
'Jul':'07',
'Aug':'08',
'Sep':'09',
'Oct':'10',
'Nov':'11',
'Dec':'12'}


UNREASANABLE_SIZE = 100*1024*1024 #100MB
NORMAL_HTTP_METHODS = ["GET", "HEAD", "POST"]
VALID_HTTP_METHODS = ["OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "VERSION-CONTROL", "REPORT", "CHECKOUT", "CHECKIN", "UNCHECKOUT", "MKWORKSPACE", "UPDATE", "LABEL", "MERGE", "BASELINE-CONTROL", "MKACTIVITY", "ORDERPATCH", "ACL"]

def parse_line(line):
    parts = shlex.split(line)
    res = {}
    res["host"] = parts[0]
    res["user"] = parts[2]

    date  = parts[3][1:] 

    date_parts = date.split("/")
    date_parts2 = date_parts[2].split(":")

    res["time"] = date_parts2[0] +'-'+months[date_parts[1]]+'-'+date_parts[0] + "T" + date_parts2[1] + ":" + date_parts2[2] + ":" + date_parts2[3] + "Z"

    res["method"] = parts[5].split()[0]
    res["request"] = parts[5].split()[-2]
    res["http_ver"] = parts[5].split()[-1]

    res["status"] = int(parts[6])

    if res["method"] not in VALID_HTTP_METHODS:
        print "ignoring request with invalid method %s in %s"%(res["method"],line)
        return None
    elif res["method"] not in NORMAL_HTTP_METHODS:
        print "abnormal http request, somebody messing around?:", line

    if parts[8] == "-":
        res["size"] = 0
    else:
        res["size"] = int(parts[8][1:-1])

    #just to observe the illogically large sizes
    if (res["size"] >= UNREASANABLE_SIZE):
        print "unreasonably large payload ", line
        return None

    if parts[9] == "-":
        res["client_request_host"] = None
    else:
        res["client_request_host"] = parts[9]


    #we guess the type from the request then
    res["type"] = res["request"].find('.', res["request"].rfind('/')) == -1 and 'html' or res["request"].split('.')[-1]
    #group all the images
    res["type"] = res["type"] in ["jpg", "gif", "png"] and "image" or res["type"]

    res["agent"] = parts[10]

    #pdb.set_trace()   
    return res