#!/usr/bin/env python

__author__ = "benj.renard@gmail.com"

import logging
import threading

import hashlib
from util.crypto import decrypt

import zmq
from zmq.eventloop import ioloop, zmqstream

class LogFetcher(threading.Thread):

    def __init__(self, conf_options):
        self.BOTBANGER_LOG = "botbanger_log"        
        self.GREYMEMORY_INFO = "greymemory_info"
        
        for sniffer in conf_options['sniffers']:
            print sniffer
            context = zmq.Context()
            self.socket = context.socket(zmq.SUB)
            subscriber = zmqstream.ZMQStream(self.socket)
            self.socket.setsockopt(zmq.SUBSCRIBE, sniffer['queue'])
            self.socket.connect(sniffer['bindstring'])
            threading.Thread.__init__(self)
            subscriber.on_recv(self.subscription)
            self.loop = ioloop.IOLoop.instance()
            key = hashlib.sha256(sniffer['passphrase'])
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
    
            message = zmq_decrypted 
            #logging.debug("decrypted message: %s"%message)
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
