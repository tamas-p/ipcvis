#!/usr/bin/python

import os, sys, time

# r, w = os.pipe() 

processid = os.fork()
if processid:
    os.wait()
    time.sleep(10000)
else:
    processid = os.fork()
    time.sleep(10000)
