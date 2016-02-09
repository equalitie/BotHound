"""
Simply a class to store data from ATS log. because it is used in multiple 
project it was better to store it in a separate file
"""
from time import strptime, mktime

class ATSRecord:
    """
    This is to keep the info from one ATS record. For now we only extract
    the time but this can be change.

    INPUT:
        cur_rec_dict: a dictionary resulted from
    TODO::
    We probably shouldn't read the whole table. There should be a way to
    temporally restrict the inspected data
    """
    #ATS_TIME_FORMAT = '%d/%b/%Y:%H:%M:%S'
    ATS_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'
    ATS_NO_FIELDS = 8 #maximum field index + 1 of the tokenized payload being
                      #used in the feauter computation
    #to decide that the session is dead and we need to start a new session

    def __init__(self, cur_rec_dict):
        self.ip = cur_rec_dict["host"]
        self.time = cur_rec_dict["time"];
        self.payload = cur_rec_dict;
        self.agent = cur_rec_dict["agent"]

        #do not run lexify it is slow
        #self.lexify()

    def lexify(self):
        """
        Stores tockenize version of  the payload in a array
        """
        try:
            self.tokenised_payload = shlex.split(self.payload, posix=False)
            #The posix=False will help with ignoring single single quotes
            #Other soltions:
            #1. getting rid of '
            #parsed_string.replace('\'','')

            #2. Use the shlex.shlex instead and tell it to ignore '
            # lex = shlex.shlex(str(self.payload))
            # lex.quotes = '"'
            # lex.whitespace_split = '.'
            # tokenised_payload = list(lex)
        #return '' if len(tokenised_payload) <= 0 else tokenised_payload[payloadIndex]
            if len(self.tokenised_payload) <= 0:
                self.tokenized_payload = [''] * ATS_NO_FIELDS
        except ValueError, err:
            print(str(err))
            #for debug purpose
            print self.payload
            return '' #Return empty in case of error maintainig normal
                      #behavoir so the program doesn't crash
    def get_UA(self):
        """
        Return the User Agent for this payload
        """
        return self.payload["agent"]

    def time_to_second(self):
        """
        convert the time value to total no of seconds passed
        since ???? to facilitate computation.
        """
        #find to ignore time-zone
        try:
            digested_time = strptime(self.time[:self.time.find('Z')], self.ATS_TIME_FORMAT)
        except (ValueError):
            print "time is ", self.time

        return mktime(digested_time)

    def get_doc_type(self):
        """
        Retrieves the document type, if present, for the current payload
        """
        return self.payload["type"]

    def get_payload_size(self):
        """
        Retrieves the payload size, if present, for the current payload
        """
        return self.payload["size"]

    def get_http_status_code(self):
        """
        Retrieves the HTTP status code, if present, for the current payload
        """
        return self.payload["status"]

    def get_requested_element(self):
        """
        Retrieves the requested uri, if present, for the current payload
        """
        return self.payload["request"]

    def get_requested_host(self):
        """
        Retrieves the requested target domain, if present, for the current payload
        """
        return self.payload["client_request_host"]

