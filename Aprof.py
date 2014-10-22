import sys
import glob

from Aprof.Profiler import *

# Look for '-s devid' flag
for i in xrange(1, len(sys.argv) - 1):
	if sys.argv[i] == '-s':
		# Set ANDROID_SERIAL to force adb to use the indicated device
		os.environ['ANDROID_SERIAL'] = sys.argv[i + 1]
		break

localfiles = []
for i in xrange(1, len(sys.argv) - 1):
	localfiles += glob.glob(sys.argv[i])
p = Profiler(localfiles, sys.argv[-1])
p.dump_csv(sys.stdout)
p.close()