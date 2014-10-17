#!/usr/bin/env python

import glob
import re
import os
import sys
import subprocess
import struct
import array

def Verbose(msg):
	pass

def Warning(msg):
	print 'WARNING: %s' % msg

def Fatal(msg):
	print 'ERROR: %s' % msg
	sys.exit(1)

class ModCache:
	def __init__(self, localfiles=[]):
		# If .aprof_cache directory doesn't exist, create it
		self._cachepath = '.aprof_cache'
		if not os.path.isdir(self._cachepath):
			os.makedirs(self._cachepath)
		self._local = {}
		self._localoverride = localfiles
		
	def get(self, filename, fresh=False):
		if self._local.has_key(filename):
			return self._local[filename]
		# Is there a local override?
		target = self.get_local(filename)
		if not target:
			# Not a local file
			cachename = filename.replace('/', '__')
			target = os.path.join(self._cachepath, cachename)
			# If we've been requested to get a fresh copy, or the file isn't in the
			# cache yet, pull it from the device
			if fresh or not os.path.isfile(target):
				args = ['adb', 'pull', filename, target]
				p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				p.communicate()
				if p.returncode or not os.path.isfile(target):
					Warning('failed to download %s' % filename)
					return None
		self._local[filename] = target
		return target
		
	def get_local(self, filename):
		for f in self._localoverride:
			(dir, fn) = os.path.split(f)
			afn = filename.split('/')[-1]
			if fn == afn:
				if not os.path.isfile(f):
					Warning('local file %s doesn\'t exist, ignoring' % f)
					continue
				return f
		return None

class Demangler:
	def __init__(self):
		args = ['arm-linux-androideabi-c++filt']
		self._demangler = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		
	def demangle(self, sym):
		if not self._demangler:
			return sym
		self._demangler.stdin.write('%s\n' % sym)
		return self._demangler.stdout.readline().strip()
		
	def close(self):
		self._demangler.stdin.close()
		self._demangler = None
		
class SymbolResolver:
	def __init__(self, remotepath, modcache):
		self._remotepath = remotepath
		self._symbols = []
		self._ok = False
		
		localpath = modcache.get(self._remotepath)
		if not localpath:
			Warning('won\'t be able to resolve symbols inside %s' % self._remotepath)
			return
		args = ['arm-linux-androideabi-readelf', '-s', '-W', localpath]
		p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(out, errout) = p.communicate()
		if p.returncode:
			Warning('Module %s is not a valid ELF file' % self._remotepath)
			return
		symre = re.compile(r'\s+')
		for sl in map(str.strip, out.split('\n')):
			fields = symre.split(sl)
			if len(fields) == 8 and fields[0] != 'Num:':
				symaddr = int(fields[1], 16)
				symsize = int(fields[2])
				symname = fields[7]
				self._symbols.append((symaddr, symsize, symname))
		self._ok = True
					
	def resolve(self, addr):
		if not self._ok:
			return None
		for (symaddr, symsize, symname) in self._symbols:
			if addr >= symaddr and addr < symaddr + symsize:
				return symname
		return None
		
	def close(self):
		pass
		
class LineResolver:
	def __init__(self, remotepath, modcache):
		self._remotepath = remotepath
		self._ok = False
		
		localpath = modcache.get(self._remotepath)
		if not localpath:
			Warning('won\'t be able to resolve line numbers inside %s' % self._remotepath)
			return
		# Test out addr2line to see if it works
		args = ['arm-linux-androideabi-addr2line', '-C', '-e', localpath, '123']
		a2ltest = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		a2ltest.communicate()
		if a2ltest.returncode:
			Warning('Module %s is not a valid ELF file' % self._remotepath)
			return
		# Now start it for real
		args = ['arm-linux-androideabi-addr2line', '-C', '-e', localpath]
		self._a2l = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self._ok = True
		
	def resolve(self, addr):
		if not self._ok:
			return None
		query = '0x%x\n' % addr
		self._a2l.stdin.write(query)
		response = self._a2l.stdout.readline().strip()
		if response == '??:0':
			response = None
		return response
		
	def close(self):
		if not self._ok:
			return
		self._a2l.stdin.close()
		self._a2l = None
		self._ok = False
		
class Module:
	def __init__(self, remotepath, modcache):
		self._remotepath = remotepath
		self._symbol_resolver = None
		self._line_resolver = None
		self._modcache = modcache
		self._mappings = []
		self._segvma = {}
		self._ok = False # We flag whether we successfully loaded the module

		# Get segment VMAs. Because shared objects can be relocated, we can't assume that load address == VMA,
		# but we can correct for relocation by matching up the "offset" field in the mapping with the offset of the
		# segment in the ELF file. We don't have the mappings yet (they will be added with add_map)
		# but we store away a lookup table from offset -> VMA.
		localpath = self._modcache.get(self._remotepath)
		if not localpath:
			Warning('Module %s could not be found (make sure the device is connected)' % self._remotepath)
			return
		p = subprocess.Popen(['arm-linux-androideabi-readelf', '-l', '-W', localpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(out, errout) = p.communicate()
		if p.returncode:
			Warning('Module %s is not a valid ELF file' % self._remotepath)
			return
		loadre = re.compile(r'\s*LOAD\s+(0x\S+)\s+(0x\S+).*')
		for ll in out.split('\n'):
			mat = loadre.match(ll)
			if mat:
				offset = long(mat.group(1), 16)
				vma = long(mat.group(2), 16)
				self._segvma[offset] = vma
		self._ok = True
	
	def add_map(self, begin, end, offset, perm):
		if not self._ok:
			return
		if offset not in self._segvma:
			# Some unknown region of the file was mapped. Ignore it
			Verbose('ignoring strange mapping: %s+0x%x' % (self._remotepath, offset))
			return
		# Compute the "tweak" we need to add to correct for relocation of this segment
		tweak = self._segvma[offset] - begin
		self._mappings.append((begin, end, tweak))
	
	def get_vma(self, addr):
		for (begin, end, tweak) in self._mappings:
			if addr >= begin and addr < end:
				return addr + tweak
		return None
		
	def get_symbol(self, addr):
		for (begin, end, tweak) in self._mappings:
			if addr >= begin and addr < end:
				return self._get_symbol_resolver().resolve(addr + tweak)
		return None
	
	def get_line(self, addr):
		for (begin, end, tweak) in self._mappings:
			if addr >= begin and addr < end:
				return self._get_line_resolver().resolve(addr + tweak)
		return None
		
	def close(self):
		if self._symbol_resolver:
			self._symbol_resolver.close()
			self._symbol_resolver = None
		if self._line_resolver:
			self._line_resolver.close()
			self._line_resolver = None
		
	def _get_symbol_resolver(self):
		if not self._symbol_resolver:
			self._symbol_resolver = SymbolResolver(self._remotepath, self._modcache)
		return self._symbol_resolver
	
	def _get_line_resolver(self):
		if not self._line_resolver:
			self._line_resolver = LineResolver(self._remotepath, self._modcache)
		return self._line_resolver
		
class HitCounter:
	def __init__(self):
		self._count = {}
		
	def hit(self, key):
		self._count[key] = self._count.get(key, 0) + 1

	def get_hits(self):
		return [(count, key) for key, count in self._count.items()]
		
class Profiler:
	def __init__(self, localfiles, profiledatafile):
		self._modcache = ModCache(localfiles)
		self._modules = {}
		self._symcache = {}
		self._linecache = {}
		self._demangler = Demangler()
		self._demanglecache = {}
		self._modhitcounter = HitCounter()
		self._symhitcounter = HitCounter()
		self._combinedhitcounter = HitCounter()

		self._parseprofile(profiledatafile)
		self._buildhits()
		
	def _parseprofile(self, profiledatafile):
		f = open(profiledatafile, 'rb')
		chunkid = f.read(8)
		
		# Read the PROFDAT1 chunk which contains the PC samples
		if chunkid != 'PROFDAT1':
			Fatal('corrupted file: bad chunk ID (expected PROFDAT1)')
		pcsize = f.read(4)
		if len(pcsize) != 4:
			Fatal('corrupted file: too short')
		self._pcsize = struct.unpack('<I', pcsize)[0]
		if self._pcsize != 4 and self._pcsize != 8:
			Fatal('corrupted file: crazy PC size')
		nsamps = f.read(8)
		if len(nsamps) != 8:
			Fatal('corrupted file: too short')
		self._nsamps = struct.unpack('<Q', nsamps)[0]
		# Read the actual samples
		if self._pcsize != 4:
			# This is irritating. array.array doesn't support 64-bit integers.
			Fatal('64-bit Android is not supported yet')
		samps = array.array('L')
		try:
			samps.fromfile(f, self._nsamps)
		except Exception as e:
			Fatal('corrupted file: %s' % e)
		self._samples = samps.tolist()
		
		# Read the MAPSDATA chunk which contains the mapping information
		mapsid = f.read(8)
		if mapsid != 'MAPSDATA':
			Fatal('corrupted file: no MAPSDATA chunk')
		# Next 4 bytes supposed to contain the size of MAPSDATA, but they aren't written correctly
		# by libAprof yet. So we ignore them, and read to end of file.
		if len(f.read(4)) != 4:
			Fatal('corrupted file: too short')
		maps = f.read()
		
		self._parsemaps(maps)
		
	def _buildhits(self):
		# Build the hit tables for module, symbol, and line
		for pc in self._samples:
			(mod, sym) = self.get_symbol(pc)
			line = self.get_line(pc)
			if not mod:
				mod = '<unknown>'
			if not sym:
				sym = '<unknown>'
			if not line:
				line = '<unknown>'
			self._modhitcounter.hit(mod)
			self._symhitcounter.hit((mod, sym))
			self._combinedhitcounter.hit((mod, sym, line))
	
	def get_symbol(self, addr):
		if self._symcache.has_key(addr):
			return self._symcache[addr]
		containing_mod = None
		for (modname, m) in self._modules.items():
			# Try to get the VMA of this address, so we can at least report which module the symbol comes
			# from
			vma = m.get_vma(addr)
			if vma is not None:
				# VMA lookup succeeded, so remember this as the right module
				containing_mod = modname
			sym = m.get_symbol(addr)
			if sym:
				self._symcache[addr] = (modname, sym)
				return (modname, sym)
		result = (containing_mod, None)
		self._symcache[addr] = result
		return result

	def get_line(self, addr):
		if self._linecache.has_key(addr):
			return self._linecache[addr]
		for (modname, m) in self._modules.items():
			line = m.get_line(addr)
			if line:
				self._linecache[addr] = line
				return line
		self._linecache[addr] = None
		return None
		
	def demangle(self, sym):
		if self._demanglecache.has_key(sym):
			return self._demanglecache[sym]
		dsym = self._demangler.demangle(sym)
		self._demanglecache[sym] = dsym
		return dsym
		
	def _parsemaps(self, maps):
		# Parse the maps
		mapre = re.compile(r'([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+(....)\s+([0-9a-fA-F]+)\s+\S+\s+\S+\s+(.+)')
		for ml in maps.split('\n'):
			mat = mapre.match(ml)
			if mat:
				begin = long(mat.group(1), 16)
				end = long(mat.group(2), 16)
				perm = mat.group(3)
				offset = long(mat.group(4), 16)
				modpath = mat.group(5)
				# Exclude unacceptable modules
				if perm[2] != 'x':
					continue
				if modpath[:5] == '/dev/':
					continue
				if modpath == '[vectors]':
					continue
				if modpath not in self._modules:
					self._modules[modpath] = Module(modpath, self._modcache)
				self._modules[modpath].add_map(begin, end, offset, perm)
		
	def dump_csv(self, f):
		print >> f, 'Module,Samples,Percent'
		modhits = self._modhitcounter.get_hits()
		modhits.sort()
		modhits.reverse()
		total = sum([count for count, x in modhits])
		if total > 0:
			for (count, modname) in modhits:
				percent = 100.0 * count / total
				print >> f, '%s,%d,%0.2f' % (modname, count, percent)
				
		print >> f
		print >> f, 'Module,Symbol,Samples,Percent'
		symhits = self._symhitcounter.get_hits()
		symhits.sort()
		symhits.reverse()
		total = sum([count for count, x in symhits])
		if total > 0:
			for (count, (modname, sym)) in symhits:
				percent = 100.0 * count / total
				print >> f, '%s,"%s",%d,%0.2f' % (modname, self.demangle(sym), count, percent)
				
		print >> f
		print >> f, 'Module,Symbol,File,Line,Samples,Percent'
		combhits = self._combinedhitcounter.get_hits()
		combhits.sort()
		combhits.reverse()
		total = sum([count for count, x in combhits])
		if total > 0:
			for (count, (modname, sym, line)) in combhits:
				if line == '<unknown>':
					(file, line) = ('<unknown>', '<unknown>')
				else:
					colon = line.rfind(':')
					(file, line) = (line[:colon], line[colon+1:])
				percent = 100.0 * count / total
				print >> f, '%s,"%s",%s,%s,%d,%0.2f' % (modname, self.demangle(sym), file, line, count, percent)
				
	def close(self):
		for m in self._modules.values():
			m.close()
		self._modules = {}
		self._demangler.close()
		
localfiles = []
for i in xrange(1, len(sys.argv) - 1):
	localfiles += glob.glob(sys.argv[i])
p = Profiler(localfiles, sys.argv[-1])
p.dump_csv(sys.stdout)
p.close()