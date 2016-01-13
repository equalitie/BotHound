import unittest
from bothound_live_sniffer import BothoundLiveSniffer
from apache_log_muncher import parse_line

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
            message = parse_line(line)
            self.sniffer._clusterify(message)
        self.assert_(True);