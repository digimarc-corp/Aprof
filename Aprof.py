import sys
import glob

sys.path.append('.')

from Aprof.Profiler import *

localfiles = []
for i in xrange(1, len(sys.argv) - 1):
	localfiles += glob.glob(sys.argv[i])
p = Profiler(localfiles, sys.argv[-1])
p.dump_csv(sys.stdout)
p.close()