import sys
import re

bytecount = {}
callcount = {}

framere = re.compile(r'#1\s.* in (.*)')
nbytere = re.compile(r'\$[0-9]+ = (.*)')
fp = open(sys.argv[1], 'r')
frame = None
nbyte = None
for line in map(str.strip, fp.xreadlines()):
	mat = framere.match(line)
	if mat:
		frame = mat.group(1)
	mat = nbytere.match(line)
	if mat:
		nbyte = int(mat.group(1))
	if frame is not None and nbyte is not None:
		callcount[frame] = callcount.get(frame, 0) + 1
		bytecount[frame] = bytecount.get(frame, 0) + nbyte
		frame = None
		nbyte = None

print 'Context,Calls,BytesCopied'
for frame in callcount:
	count = callcount[frame]
	nbyte = bytecount[frame]
	print '"%s",%d,%d' % (frame, count, nbyte)
