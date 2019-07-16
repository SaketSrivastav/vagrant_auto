#!/usr/bin/python
import logging
import sys
import os
from parameterized import parameterized

@parameterized ([(1,2), (2,3)])
def test_sample(a, b):
    logging.info("info")
    logging.debug("debug")
    #logging.warn("warn")
    #logging.critical("critical")
    #logging.info("Done test")
def test_sample2():
    logging.info("info")
    logging.debug("debug")
 
