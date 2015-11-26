#!/usr/bin/env python

__author__ = "benj.renard@gmail.com"

import logging
import optparse
import re
import sys
import threading

import hashlib
from crypto import decrypt

import zmq
from zmq.eventloop import ioloop, zmqstream

class LogFetcher(threading.Thread):

    def __init__(self, bindstrings, conf_file, verbose=False):
        #TODO: can the context be shared, what about subscriber
        self.BOTBANGER_LOG = "botbanger_log" #class constants don't
        #survive inheritance

        context = zmq.Context()
        self.socket = context.socket(zmq.SUB)
        subscriber = zmqstream.ZMQStream(self.socket)
        self.socket.setsockopt(zmq.SUBSCRIBE, self.BOTBANGER_LOG)
        self.socket.connect(bindstrings)
        threading.Thread.__init__(self)
        subscriber.on_recv(self.subscription)
        self.loop = ioloop.IOLoop.instance()
        passphrase = 'drawnandquarterly'
        key = hashlib.sha256(passphrase)
        self.hashed_key = key.digest()
        print ord(self.hashed_key[0])

    def subscription(self, zmq_message):
        action, encrypted_message = zmq_message;
        #decrypt the message here
        zmq_iv = zmq_message[0:12]
        zmq_cipher = zmq_message[12:-16] 
        zmq_tag = zmq_message[-16:]        
        zmq_decrypted = decrypt(self.hashed_key, "", zmq_iv, zmq_cipher, zmq_tag)
        print zmq_decrypted
        
        message = zmq_decrypted.split(',') 
                
        return process_received_message(self, message);

    def process_received_message(self, message):
        print message
        
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

    parser.add_option("-B", "--bindstrings",
                      action="store", dest="bindstrings",
                      default="tcp://127.0.0.1:22621",
                      help="URI to bind to")

    parser.add_option("-S", "--subscriptions",
                      action="store", dest="subscriptions",
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
