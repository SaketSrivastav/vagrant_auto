import sys
import logging
from scapy.all import *
sys.path.append('.')
reload(sys)

from helper import *

if (len(sys.argv) == 2):
    conf.iface =  sys.argv[1]
else :
    print("\nbfd_test.py <iface>\n")
    sys.exit(1)

logging.basicConfig(format='', level=logging.DEBUG)
logging.basicConfig(format='', level=logging.INFO)
NetworkUtil.BFDResponder(conf.iface)
