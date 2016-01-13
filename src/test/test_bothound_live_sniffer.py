import unittest
from bothound_live_sniffer import BothoundLiveSniffer

class BothoundLiveSnifferTestCase(unittest.TestCase):
    def setUp(self):
        conf_options = {'sniffers':{}}
        self.sniffer = BothoundLiveSniffer(conf_options)

    def tearDown(self):
        self.sniffer = None

    def test_process_decoded_message(self):
        print "Calling _process_decoded_message"
        f = open('logfetcher.log', 'r')
        for line in f:
            decoded_message = line.split(' ')
            self.sniffer._process_decoded_message(decoded_message)
        self.assert_(1 == 1);