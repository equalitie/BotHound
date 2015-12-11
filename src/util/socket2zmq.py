#!/usr/bin/env python

from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
import optparse
import zmq
import hashlib

from crypto import encrypt

### Protocol Implementation

class SocketToZmq(Protocol):
    def __init__(self, zmq_socket,passphrase):
        # Prepare our context and publisher
        self.context   = zmq.Context()
        self.publisher = self.context.socket(zmq.PUB)
        self.publisher.bind(zmq_socket)

        key = hashlib.sha256(passphrase)
        self.hashed_key = key.digest()


    def dataReceived(self, data):
        """
        As soon as any data is received, write it into zmq socket.
        """
        print data
        iv, ciphertext, tag = encrypt(self.hashed_key,data, "")

        self.publisher.send_multipart(["greymemory_info", iv + ciphertext + tag])

class SocketToZmqFactory(Factory):
    def buildProtocol(self, addr):
        return SocketToZmq(self.zmq_socket,self.passphrase);

    def __init__(self, zmq_socket, passphrase):
        self.zmq_socket = zmq_socket
        self.passphrase = passphrase

def main():
    parser = optparse.OptionParser()

    parser.add_option("-Z", "--zmqport",
                      action="store", dest="zmqport",
                      default=22622,
                      help="ZMQ socket port")

    parser.add_option("-P", "--port",
                      action="store", dest="port",
                      default=22623,
                      help="TCP socket port")

    (options, args) = parser.parse_args()

    f = SocketToZmqFactory("tcp://*:%s" % options.zmqport, "drawnandquarterly")
    print "Listening on port %s, publishing on ZMQ port %s ..." % (options.port, options.zmqport)
    f.protocol = SocketToZmq
    reactor.listenTCP(options.port, f)
    reactor.run()

if __name__ == '__main__':
    main()
