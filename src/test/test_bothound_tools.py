import unittest, sys, yaml, hashlib, hmac, pdb
from os.path import dirname, abspath


try:
    src_dir = dirname(dirname(abspath(__file__)))
except NameError:
    #the best we can do to hope that we are in the test dir
    src_dir = dirname(getcwd())

sys.path.append(src_dir)

from util.crypto import decrypt
from bothound_tools import BothoundTools

class BothoundToolsTestCase(unittest.TestCase):
    def setUp(self):
        stram = open("test/bothound_test.yaml", "r")
        conf = yaml.load(stram)
        
        self.enc_key = hashlib.sha256(conf["database"]["encryption_passphrase"]).digest()
        self.hash_key = hashlib.sha256(conf["database"]["hash_passphrase"]).digest()
        self.bothound_tools = BothoundTools(conf)

        self.sensetive_data = "127.0.0.1"
        self.hmacced = "\xc3\x8a\x81\x9eY\x9e\xdf[\xee\xd6\xbce\x99F&<\xb3\xc9|t'\xbb9\xef\x9cU>k$}lg"
 
    def tearDown(self):
        pass

    def test_encrypt_sensetive_data(self):
        pdb.set_trace()
        enc_and_hash = self.bothound_tools.encrypt_and_hash_to_store(self.sensetive_data)

        

        assert(decrypt(self.enc_key, "", enc_and_hash[0][0], enc_and_hash[0][1], enc_and_hash[0][2]) == self.sensetive_data)
        assert(hmac.new(self.sensetive_data, self.hash_key, hashlib.sha256).digest() == self.hmacced)

if __name__ == "__main__":
    unittest.main()
