#!/usr/bin/env python

import sys
import glob
import time

from Aprof.Debugger import *

localfiles = []
for i in xrange(1, len(sys.argv) - 1):
	localfiles += glob.glob(sys.argv[i])
d = Debugger(localfiles, sys.argv[-1])
d.close()