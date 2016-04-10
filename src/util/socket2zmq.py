#!/usr/bin/env python

from twisted.internet.protocol import Protocol, Factory
from twisted.protocols import basic
from twisted.internet import reactor
import optparse
import zmq
import hashlib

from crypto import encrypt

### Protocol Implementation

class SocketToZmq(basic.LineReceiver):
    delimiter = '\n'

    def __init__(self, factory):
        self.factory = factory

    def lineReceived(self, line):
        # Ignore blank lines
        if not line: return
        """
        As soon as any line is received, write it into zmq socket.
        """
        print line
        iv, ciphertext, tag = encrypt(self.factory.hashed_key,line, "")
        self.factory.publisher.send_multipart([self.factory.zmq_tag, iv + ciphertext + tag])

class SocketToZmqFactory(Factory):
    def buildProtocol(self, addr):
        return SocketToZmq(self);

    def __init__(self, zmq_socket, passphrase, zmq_tag):
        # Prepare our context and publisher
        self.context   = zmq.Context()
        self.publisher = self.context.socket(zmq.PUB)
        self.publisher.bind(zmq_socket)
        self.zmq_tag = zmq_tag

        key = hashlib.sha256(passphrase)
        self.hashed_key = key.digest()

def main():
    parser = optparse.OptionParser()

    parser.add_option("-Z", "--zmqport",
                      action="store", dest="zmqport",
                      default=22624,
                      help="ZMQ socket port")

    parser.add_option("-G", "--greymemoryport",
                      action="store", dest="port",
                      default=22623,
                      help="TCP socket port")

    parser.add_option("-P", "--passphrase",
                      action="store", dest="passphrase",
                      default="drawnandquarterly",
                      help="Passphrase")

    parser.add_option("-T", "--zmqtag",
                      action="store", dest="zmqtag",
                      default="greymemory_info",
                      help="Zmq tag for messages")

    (options, args) = parser.parse_args()

    f = SocketToZmqFactory("tcp://*:%s" % options.zmqport, options.passphrase, options.zmqtag)
    print "ZMQ relay service."
    print "Listening on port %s, relaying to ZMQ port %s ..." % (options.port, options.zmqport)
    reactor.listenTCP(options.port, f)
    reactor.run()

if __name__ == '__main__':
    main()
