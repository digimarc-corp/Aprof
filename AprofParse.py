#!/usr/bin/env python

import sys
import subprocess
import struct
import re
import os

try:
	import colorama
	colorama.init()
	import termcolor

	def PrintColor(msg, fg=None, bg=None):
		termcolor.cprint(msg, fg, bg)
		
	def E(msg):
		return termcolor.colored(msg, 'red', attrs=['bold'])
		
	def CYAN(msg):
		return termcolor.colored(msg, 'cyan', attrs=['bold'])

	def GREEN(msg):
		return termcolor.colored(msg, 'green', attrs=['bold'])
		
	def WHITE(msg):
		return termcolor.colored(msg, 'white', attrs=['bold'])
		
	def MAGENTA(msg):
		return termcolor.colored(msg, 'magenta', attrs=['bold'])

	def YELLOW(msg):
		return termcolor.colored(msg, 'yellow', attrs=['bold'])

	def RED(msg):
		return termcolor.colored(msg, 'red', attrs=['bold'])

	ansi_escape = re.compile(r'\x1b[^m]*m')
	
	def DECOLOR(msg):
		global ansi_escape
		return ansi_escape.sub('', msg)

except ImportError:
	def PrintColor(msg, fg=None, bg=None):
		print msg
	
	def E(msg):
		return msg
		
	def CYAN(msg):
		return msg

	def GREEN(msg):
		return msg

	def WHITE(msg):
		return msg
		
	def MAGENTA(msg):
		return msg

	def YELLOW(msg):
		return msg
		
	def RED(msg):
		return msg
		
	def DECOLOR(msg):
		return msg

optMergeLineCounts = True
optTopPercent = 0

def GetTextStart(fn):
	splitter = re.compile(r'\s*(\S+)\s*(0x.*)\s+(0x.*)\s+(0x.*)\s+(0x.*)\s+(0x.*)\s+(.)(.)(.)\s+(0x.*)')
	readelf = subprocess.Popen(['arm-linux-androideabi-readelf', '-l', fn], stdout=subprocess.PIPE)
	elfdata = readelf.stdout.read()
	inLoadSegments = False
	for line in elfdata.split('\n'):
		line = line.strip()
		if not inLoadSegments:
			if line == 'Program Headers:':
				inLoadSegments = True
		else:
			mat = splitter.match(line)
			if mat and mat.group(1) == 'LOAD' and mat.group(9) == 'E':
				return int(mat.group(3), 16)

def ReadSymTab(fn):
	splitter = re.compile(r'\s+')
	readelf = subprocess.Popen(['arm-linux-androideabi-readelf', '-s', '-W', fn], stdout=subprocess.PIPE)
	elfdata = readelf.stdout.read()
	inSymbols = 0
	syms = []
	for line in elfdata.split('\n'):
		line = line.strip()
		if inSymbols == 0:
			if line[:6] == 'Symbol':
				inSymbols = 1
		elif inSymbols == 1:
			if line[:6] == 'Symbol':
				inSymbols = 1
			else:
				inSymbols = 2
		else:
			if line[:6] == 'Symbol':
				inSymbols = 1
			else:
				fields = splitter.split(line)
				if len(fields) == 8:
					addr = long(fields[1], 16)
					size = long(fields[2])
					name = fields[7]
					syms.append((addr, size, name))
	syms.sort()
	return syms
	
def FindSym(syms, addr):
	for s in syms:
		if addr >= s[0] and addr < s[0] + s[1]:
			return s[2]
	return None
				
# Get name of binary
bin = sys.argv[1]

# Open the PROFDATA file
pdata = open(sys.argv[2], 'rb')
sig = pdata.read(8)
if sig != 'PROFDAT1':
	print 'ERROR: %s is not a PROFDAT1 file' % sys.argv[2]
	sys.exit(1)
# Parse the size byte (32-bit or 64-bit)
sizebyte = ord(pdata.read(1))
pdata.read(3)
# Set up address format
addrfmt = '%%0%dX' % (2 * sizebyte)
# Parse the sample count
samplecountbuf = pdata.read(8)
samplecount = struct.unpack('Q', samplecountbuf)[0]

# Clear the hash of counts
counts = {}

# Open the addr2line executable
a2l = subprocess.Popen(['arm-linux-androideabi-addr2line', '-e', bin], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

# Parse the data
nsamps = 0
while nsamps < samplecount:
	# Read next sample
	addrbytes = pdata.read(sizebyte)
	if len(addrbytes) != sizebyte:
		print 'ERROR: truncated file'
		sys.exit(1)
	nsamps += 1
	# Update hash
	counts[addrbytes] = counts.get(addrbytes, 0) + 1
	continue
	
	# Convert the pc bytes to a string format
	str = ''
	for i in xrange(sizebyte):
		str = '%02X%s' % (ord(addrbytes[i]), str)
	# Send the address to addr2line and get translated result
	a2l.stdin.write('%s\n' % str)
	line = a2l.stdout.readline().strip()
	line = '%s/%s' % (line, str)
	# Increment hit count in the hash
	counts[line] = counts.setdefault(line, 0) + 1
	nsamps += 1
	
# Read the maps data
mapsdatasig = pdata.read(8)
if mapsdatasig != 'MAPSDATA':
	print 'ERROR: %s does not contain MAPSDATA' % sys.argv[2]
	print mapsdatasig
	sys.exit(1)
# Read the string length placeholder
pdata.read(8)
# Read the remainder of the file into mapsdata
mapsdata = pdata.read()

pdata.close()

# Parse the maps data to produce two dictionaries: modules_begin and modules_end,
# which contain the known extent of each file module. We will use these ranges
# later to try to resolve addresses in other modules
modules_begin = {}
modules_end = {}
mapre = re.compile(r'(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S*)')
for m in mapsdata.split('\n'):
	mat = mapre.match(m)
	# Look for matches with a filename (path beginning with '/') but not from /dev
	if mat and mat.group(2)[2] == 'x' and mat.group(6) and mat.group(6)[0] == '/' and mat.group(6)[:5] != '/dev/':
		(b, e) = mat.group(1).split('-')
		begin = long(b, 16)
		end = long(e, 16)
		modfile = mat.group(6)
		if modules_begin.has_key(modfile):
			modules_begin[modfile] = min(modules_begin[modfile], begin)
			modules_end[modfile] = max(modules_end[modfile], end)
		else:
			modules_begin[modfile] = begin
			modules_end[modfile] = end
			
#for k in modules_begin.keys():
#	print k

# Figure out which module is the main module
for m in modules_begin.keys():
	if m.split('/')[-1] == bin.split('/')[-1].split('\\')[-1]:
		main_begin = modules_begin[m]
		main_end = modules_end[m]
		main_module = m
		break
		
# Create addr2line instances on demand
modules_addr2line = {}
modules_tweak = {}
modules_symtab = {}

# Translate addresses to line numbers
resolvedcounts = {}
for (addrbytes, count) in counts.items():
	# Unpack the address
	if sizebyte == 4:
		addr = struct.unpack('I', addrbytes)[0]
	else:
		addr = struct.unpack('Q', addrbytes)[0]
	# Default signature
	addrstring = '??? (%X)' % addr
	# Find the module the address is part of
	module = None
	for m in modules_begin.keys():
		if addr >= modules_begin[m] and addr < modules_end[m]:
			module = m
			break
	# Did we find a module?
	if module:
		# Is there already an addr2line for this module?
		if not modules_addr2line.has_key(module):
			# No... Is it the main module?
			if module != main_module:
				# No... pull it
				localfile = module.split('/')[-1]
				cmd = 'adb pull %s 2> nul' % module
				os.system(cmd)
				if not os.path.isfile(localfile):
					print 'ERROR: could not get remote file %s' % module
				else:
					a2l = subprocess.Popen(['arm-linux-androideabi-addr2line', '-e', localfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
					modules_addr2line[module] = a2l
					modules_tweak[module] = GetTextStart(localfile)
					modules_symtab[module] = ReadSymTab(localfile)
			else:
				a2l = subprocess.Popen(['arm-linux-androideabi-addr2line', '-e', bin], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
				modules_addr2line[module] = a2l
				modules_tweak[module] = GetTextStart(bin)
				modules_symtab[module] = ReadSymTab(bin)
		a2l = modules_addr2line.get(module, None)
		if a2l:
			adjusted = addr - modules_begin[module] + modules_tweak[module]
			a2l.stdin.write('%X\n' % adjusted)
			line = a2l.stdout.readline().strip()
			# Did it resolve?
			if line == '??:0':
				# No... Can we at least use symbol name?
				line = FindSym(modules_symtab[module], adjusted)
				if not line:
					line = ''
			# Select color for line portion
			if m == main_module:
				c = GREEN
			else:
				c = YELLOW
			# Include module name, if the module isn't the main module
			depmodname = MAGENTA('(%s) ' % module)
			if m == main_module and line:
				depmodname = ''
			# If merging counts for each line, don't include address in signature
			if line and optMergeLineCounts:
				addrstring = '%s%s' % (depmodname, c(line))
			else:
				offset = CYAN('(%s)' % (addrfmt % adjusted))
				if line:
					space = ' '
				else:
					space = ''
				addrstring = '%s%s%s%s' % (depmodname, c(line), space, offset)
			
	resolvedcounts[addrstring] = resolvedcounts.get(addrstring, 0) + count

# Close the addr2line instances
for a2l in modules_addr2line.values():
	a2l.kill()
	
# Sort into descending order by hit count
accumulated = [(resolvedcounts[x], x) for x in resolvedcounts.keys()]
accumulated.sort()
accumulated.reverse()

totalhits = sum([x[0] for x in accumulated])
thresh = (totalhits * optTopPercent + 50) / 100

# Display results
print WHITE('---------- PROFILE DATA FOR %s') % bin
print
print WHITE('%-123s%s') % ('SOURCE FILE', 'COUNT')
print WHITE('-'*130)
h = 0
for (hits, addr) in accumulated:
	l = len(DECOLOR(addr))
	pad = 120 - l
	print '%s%s%8d' % (addr, ' ' * pad, hits)
	h += hits
	if optTopPercent > 0 and h >= thresh:
		break

