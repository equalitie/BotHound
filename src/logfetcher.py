#!/usr/bin/env python

__author__ = "benj.renard@gmail.com"

import logging
import optparse
import re
import sys
import threading

import hashlib
from util.crypto import decrypt

import zmq
from zmq.eventloop import ioloop, zmqstream

class LogFetcher(threading.Thread):

    def __init__(self, bindstrings, passphrase, conf_file, verbose=False):
        #TODO: can the context be shared, what about subscriber
        self.BOTBANGER_LOG = "botbanger_log" #class constants don't        
        #survive inheritance
        self.GREYMEMORY_INFO = "greymemory_info"

        bindstrings = bindstrings.split(",")
        context = zmq.Context()
        self.socket = context.socket(zmq.SUB)
        subscriber = zmqstream.ZMQStream(self.socket)
        self.socket.setsockopt(zmq.SUBSCRIBE, self.BOTBANGER_LOG)
        self.socket.connect(bindstrings[0])

        if (len(bindstrings)>1):
            self.grey_socket = context.socket(zmq.SUB)
            grey_subscriber = zmqstream.ZMQStream(self.grey_socket)
            self.grey_socket.setsockopt(zmq.SUBSCRIBE, self.GREYMEMORY_INFO)
            self.grey_socket.connect(bindstrings[1])
            grey_subscriber.on_recv(self.subscription)
            
        threading.Thread.__init__(self)
        subscriber.on_recv(self.subscription)
        self.loop = ioloop.IOLoop.instance()
        key = hashlib.sha256(passphrase)
        self.hashed_key = key.digest()
        print ord(self.hashed_key[0])

    def subscription(self, zmq_message):
        try:
                action, encrypted_message = zmq_message;
                #decrypt the message here
                zmq_iv = encrypted_message[0:12]
                zmq_cipher = encrypted_message[12:-16] 
                zmq_tag = encrypted_message[-16:]        
                zmq_decrypted = decrypt(self.hashed_key, "", zmq_iv, zmq_cipher, zmq_tag)
        
                message = zmq_decrypted.split(',') 
                logging.debug("decrypted message: %s"%message)
                
                return self.process_received_message(action, message);
        except:
            logging.error("Invalid message: %s"%zmq_message)
            return False

                

    def process_received_message(self, action, message):
        print message

        #do something with the log here                    
        pass

    def stop(self):
        self.loop.stop()

    def run(self):
        self.loop.start()
