import logging
import optparse
import sys
import yaml

from bothound_live_sniffer import BothoundLiveSniffer
from bothound_tools import BothoundTools
from session_computer import SessionComputer

from os.path import dirname, abspath
from os import getcwd
try:
    src_dir = dirname(dirname(abspath(__file__)))
except NameError:
    #the best we can do to hope that we are in the test dir
    src_dir = dirname(getcwd())

sys.path.append(src_dir)

def main():

    parser = optparse.OptionParser()
    
    parser.add_option("-v", "--verbose", dest="verbose",
            help="Be verbose in output, don't daemonise",
            default=False,
            action="store_true")

    parser.add_option("-c", "--conf",
                      action="store", dest="conffile",
                      default=src_dir+'/conf/bothound.yaml',
                      help="Path to config file")

    (parsed_options, args) = parser.parse_args()
    conf_options = {'verbose': parsed_options.verbose, 'conffile': parsed_options.conffile}

    stram = open(conf_options ['conffile'], "r")
    conf = yaml.load(stram)
    conf_options['sniffers'] = conf["sniffers"];

    if conf_options['verbose']:
        mainlogger = logging.getLogger()
        logging.basicConfig(level=logging.DEBUG)
        log_stream = logging.StreamHandler(sys.stdout)
        log_stream.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        log_stream.setFormatter(formatter)
        mainlogger.addHandler(log_stream)
    else:
        for sniffer in conf_options['sniffers']:
            logger = logging.getLogger('logfetcher')
            hdlr = logging.FileHandler(sniffer["logfile"])
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            hdlr.setFormatter(formatter)
            logger.addHandler(hdlr)
            logger.setLevel(logging.DEBUG)

    tools = BothoundTools(conf)
    tools.connect_to_db()

    session_computer = SessionComputer(tools)
    session_computer.start()

    lfetcher = BothoundLiveSniffer(conf_options, tools)
    lfetcher.run()

if __name__ == "__main__":
    main()
