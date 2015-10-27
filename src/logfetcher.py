#!/usr/bin/env python

__author__ = "benj.renard@gmail.com"

import logging
import optparse
import re
import sys
import threading

import zmq
from zmq.eventloop import ioloop, zmqstream

BOTBANGER_LOG = "botbanger_log"

class LogFetcher(threading.Thread):

    def __init__(self, bindstring, conf_file, verbose=False):
        context = zmq.Context()
        self.socket = context.socket(zmq.SUB)
        subscriber = zmqstream.ZMQStream(self.socket)
        self.socket.setsockopt(zmq.SUBSCRIBE, BOTBANGER_LOG)
        self.socket.connect(bindstring)
        threading.Thread.__init__(self)
        subscriber.on_recv(self.subscription)
        self.loop = ioloop.IOLoop.instance()

    def subscription(self, zmq_message):
        action, encrypted_message = zmq_message;

        #decrypt the message here
        action, ipaddress = message[0:2]

        ipaddress = ipaddress.strip()
        ipmatch = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        if not ipmatch.match(ipaddress):
            logging.error("Failed to validate IP address %s - rejecting",
                          ipaddress)
            return False

        if action == BOTBANGER_LOG:

            logging.debug("Received log for ip = %s", message[1])
            logging.debug("log is: %s", message)

            cur_log_rec = {}
            cur_log_rec["host"] = message[1]
            cur_log_rec["time"] = message[2]
            cur_log_rec["request"] = message[3]
            cur_log_rec["type"] = message[4]
            cur_log_rec["status"] = message[5]
            cur_log_rec["size"] = (not message[6]) and '0' or message[6]
            cur_log_rec["agent"] = message[7]
            cur_log_rec["hit"] = message[8]

            process_incoming_logs(cur_log_rec)

        else:
            logging.error("Got an invalid message header: %s", message)

    def process_incoming_logs(self, log_rec):
        #do something with the log here                    
        pass

    def stop(self):
        self.loop.stop()

    def run(self):
        self.loop.start()

def main():
    parser = optparse.OptionParser()
    parser.add_option("-v", "--verbose", dest="verbose",
                      help="Be verbose in output, don't daemonise",
                      action="store_true")

    parser.add_option("-B", "--bindstring",
                      action="store", dest="bindstring",
                      default="tcp://127.0.0.1:22621",
                      help="URI to bind to")

    parser.add_option("-L", "--logfile",
                      action="store", dest="logfile",
                      default="logfetcher.log",
                      help="File to log to")

    parser.add_option("-c", "--conf",
                      action="store", dest="conffile",
                      default="/etc/botbanger/botbanger.conf",
                      help="Path to config file")

    (options, args) = parser.parse_args()

    if options.verbose:
        mainlogger = logging.getLogger()
        logging.basicConfig(level=logging.DEBUG)
        log_stream = logging.StreamHandler(sys.stdout)
        log_stream.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        log_stream.setFormatter(formatter)
        mainlogger.addHandler(log_stream)
    else:
        logger = logging.getLogger('logfetcher')
        hdlr = logging.FileHandler(options.logfile)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        hdlr.setFormatter(formatter)
        logger.addHandler(hdlr)
        logger.setLevel(logging.DEBUG)

    lfetcher = LogFetcher(options.bindstring, options.conffile, options.verbose)
    lfetcher.run()

if __name__ == "__main__":
    main()
