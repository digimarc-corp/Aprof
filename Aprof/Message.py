import sys

def Verbose(msg):
	pass

def Warning(msg):
	print 'WARNING: %s' % msg

def Fatal(msg):
	print 'ERROR: %s' % msg
	sys.exit(1)
