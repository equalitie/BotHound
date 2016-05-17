"""
Parses a log file on the server and return the records corresponding to each client separately

AUTHORS:

 - Vmon (vmon@equalit.ie) 2012: Initial version.
 - Bill (bill.doran@gmail.com) 2012: lexify and other ATSRecord method depending on it.
 - Vmon Oct 2013: Session tracking added.

"""

from util.apache_log_muncher import parse_line as parse_apache_line
from util.nginx_log_muncher import parse_line as parse_nginx_line
from util.ats_record import ATSRecord
import util.es_log_muncher 
import pdb

class IPSieve():
    DEAD_SESSION_PAUSE  = 1800 #minimum number of seconds between two session

    def __init__(self, log_filename=None):
        self._ordered_records = {}
        self._log_file_list = []

        #This tells the sieve that needs to re-read data from the file.
        if (log_filename):
            add_log_file(self, log_filename)
        else:
            #If no file is specied then no record means all records
            self.dict_invalid = False
            self._log_lines = None #can be a file handle or array of lines

    def add_log_file(self, log_filename):
        """
        It takes the name of the log file and store it in a list
        """
        self._log_file_list.append(log_filename)
        self.dict_invalid = True

    def add_log_files(self, log_filename_list):
        """
        It takes a list of name of the log files and extend the filelist to it
        """
        self._log_file_list.extend(log_filename_list)
        self.dict_invalid = True

    def set_log_lines(self, log_lines):
        """
        It takes an array of log lines
        """
        self.dict_invalid = True
        self._log_lines = log_lines

    def set_pre_seived_order_records(self, pre_seived_records):
        """
        It sets the order records directy to the dictionary
        supplied by the user
        """
        self.dict_invalid = False
        self._ordered_records = pre_seived_records

    def parse_log(self, parser = "apache"):
        """
        Read each line of the log file and batch the records corresponding
        to each client (ip) make a dictionary of lists each consisting of all
         records
        """
        parser_function = parse_apache_line if parser == "apache" else parse_nginx_line
        #to check the performance and the sensitivity of the log mancher
        total_failure_munches = 0
        for log_filename in self._log_file_list:
            try:
                self._log_lines = open(log_filename)
            except IOError:
                raise IOError

            self._log_lines.seek(0, 2) #go to end to check the size
            total_file_size = self._log_lines.tell()
            self._log_lines.seek(0, 0) #and go back to the begining
            previous_progress = 0

            print "Parsing ", log_filename.split('/')[-1]

            #we are going to keep track of each ip and last session number corresponding
            #to that ip
            ip_session_tracker = {}
            for cur_rec in self._log_lines:
                new_session = False
                cur_rec_dict = parser_function(cur_rec)

                if cur_rec_dict:
                    cur_ip = cur_rec_dict["host"];
                    cur_ats_rec = ATSRecord(cur_rec_dict);

                    if not cur_ip in ip_session_tracker:
                        ip_session_tracker[cur_ip] = 0
                        new_session = True

                    #now we are checking if we hit a new session
                    #if we already decided that we are in a new session then there is nothing
                    #to investigate
                    if not new_session:
                        #so we have a session already recorded, compare
                        #the time of that last record of that session with
                        #this session
                        if cur_ats_rec.time_to_second() - self._ordered_records[(cur_ip, ip_session_tracker[cur_ip])][-1].time_to_second() > self.DEAD_SESSION_PAUSE:
                            #the session is dead we have to start a new session
                            ip_session_tracker[cur_ip] += 1
                            new_session = True

                    if new_session:
                        self._ordered_records[(cur_ip, ip_session_tracker[cur_ip])] = [cur_ats_rec]
                    else:
                        self._ordered_records[(cur_ip, ip_session_tracker[cur_ip])].append(cur_ats_rec)

                else:
                    #unable to munch and grasp the data due to unrecognizable format
                    total_failure_munches += 1

                #reporting progress
                current_progress = (self._log_lines.tell()*100)/total_file_size
                if (current_progress != previous_progress):
                    print "%", current_progress
                    previous_progress = current_progress


            self._log_lines.close()

        self._log_file_list = []

        #for debug, it should be moved to be dumped in the logger
        print "Parsed ", len(self._ordered_records)
        if total_failure_munches > 0:
            print "Failed to parse ", total_failure_munches, " records"
        self.dict_invalid = False
        return self._ordered_records

    def parse_log_old(self):
        """
        Read each line of the log file and batch the
        records corresponding to each (client (ip), session)
        make a dictionary of lists each consisting of all records of that session
        """
        for cur_rec in self._log_lines:
            #Here (at least for now) we only care about the ip and the time record.
            time_pos = cur_rec.find('-')
            if time_pos == -1: #Not a valid record
                continue

            http_req_pos = cur_rec.find('"')
            cur_ip = cur_rec[:time_pos-1]
            rec_time = cur_rec[time_pos + 3:http_req_pos - 2]
            rec_payload = cur_rec[http_req_pos:]
            #check if we have already encountered this ip


            cur_ats_rec = ATSRecord(cur_ip, rec_time, rec_payload)
            if not cur_ip in self._ordered_records:
                self._ordered_records[cur_ip] = [cur_ats_rec]
            else:
                self._ordered_records[cur_ip].append(cur_ats_rec)

        self.dict_invalid = False

    def process_ats_records(self, ats_records):
        print "Processing ats records... "
        #we are going to keep track of each ip and last session number corresponding
        #to that ip
        ip_session_tracker = {}
        ip_records = {}
        total_failure_munches = 0
        for cur_ats_rec in ats_records:
            new_session = False

            cur_ip = cur_ats_rec.ip

            if not cur_ip in ip_session_tracker:
                ip_session_tracker[cur_ip] = 0
                new_session = True

            #now we are checking if we hit a new session
            #if we already decided that we are in a new session then there is nothing
            #to investigate
            if not new_session:
                if cur_ats_rec.time_to_second() - ip_records[(cur_ip, ip_session_tracker[cur_ip])][-1].time_to_second() < 0:
                    print cur_ats_rec.payload, ip_records[(cur_ip, ip_session_tracker[cur_ip])][-1].payload
                    pdb.set_trace()
                               #so we have a session already recorded, compare
                #the time of that last record of that session with
                #this session
                if cur_ats_rec.time_to_second() - ip_records[(cur_ip, ip_session_tracker[cur_ip])][-1].time_to_second() > self.DEAD_SESSION_PAUSE:
                    #the session is dead we have to start a new session
                    ip_session_tracker[cur_ip] += 1
                    new_session = True

            if new_session:
                ip_records[(cur_ip, ip_session_tracker[cur_ip])] = [cur_ats_rec]
            else:
                ip_records[(cur_ip, ip_session_tracker[cur_ip])].append(cur_ats_rec)

        return ip_records

    def ordered_records(self):
        """
        Wrapper for the record dictionary
        """
        if (self.dict_invalid):
            self.parse_log()

        return self._ordered_records
