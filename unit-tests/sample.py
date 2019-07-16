import subprocess
import re
import helper

"""
def parse(tags, pattern, cmd):
    output = subprocess.check_output(cmd, shell=True)
    results = {}
    for tag in tags:
        match = re.search(r'^'+tag+pattern, output,  re.MULTILINE)
        m = match.group(0).split('\n')
        results[m[0]] = []
        for i in range(1, len(m)):
            results[m[0]].append(m[i])
    print(results)

tags = ['Available IP addresses', 'Allocated IP addresses', 'Declined IP addresses']
pattern = '$(\n^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)*'
#results = helper.parse(tags, pattern, 'cat op.txt')

pattern = '(($(\n^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})((\t)+([0-9]+)*s)?)$)*'
results = helper.parse(tags, pattern, 'cat op.txt')
print resultks
ip
"""
import time
import logging
 
logging.basicConfig(level=logging.DEBUG)
 
def test_1():
    log = logging.getLogger('test_1')
    time.sleep(1)
    log.debug('after 1 sec')
    time.sleep(1)
    log.debug('after 2 sec')
    time.sleep(1)
    log.debug('after 3 sec')
    assert 1, 'should pass'
 
def test_2():
    log = logging.getLogger('test_2')
    time.sleep(1)
    log.debug('after 1 sec')
    time.sleep(1)
    log.debug('after 2 sec')
    time.sleep(1)
    log.debug('after 3 sec')
    assert 0, 'failing for demo purposes'
