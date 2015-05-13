import struct
import array
import re

from Module import *
from ModCache import *
from Demangler import *
from HitCounter import *
from Message import *

class Profiler:
	def __init__(self, localfiles, profiledatafile):
		self._modcache = ModCache(localfiles)
		self._modules = {}
		self._symcache = {}
		self._linecache = {}
		self._vmacache = {}
		self._demangler = Demangler()
		self._demanglecache = {}
		self._modhitcounter = HitCounter()
		self._vmahitcounter = HitCounter()
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
			vma = self.get_vma(pc)
			# If VMA can't be resolved, it means PC was in a region we don't
			# know about. The module is probably unknown. Use PC directly
			# as the key in this case.
			if vma is None:
				vma = pc
			(mod, sym) = self.get_symbol(pc)
			line = self.get_line(pc)
			if not mod:
				mod = '<unknown>'
			if not sym:
				sym = '<unknown>'
			if not line:
				line = '<unknown>'
			self._modhitcounter.hit(mod)
			self._vmahitcounter.hit((mod, sym, line, vma))
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
	
	def get_vma(self, addr):
		if self._vmacache.has_key(addr):
			return self._vmacache[addr]
		vma = None
		for (modname, m) in self._modules.items():
			vma = m.get_vma(addr)
			if vma is not None:
				break
		self._vmacache[addr] = vma
		return vma
	
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
				if modpath == '[sigpage]':
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
				
		print >> f
		print >> f, 'Module,Symbol,File,Line,VMA,Samples,Percent'
		vmahits = self._vmahitcounter.get_hits()
		vmahits.sort()
		vmahits.reverse()
		total = sum([count for count, x in vmahits])
		if total > 0:
			for (count, (modname, sym, line, vma)) in vmahits:
				if line == '<unknown>':
					(file, line) = ('<unknown>', '<unknown>')
				else:
					colon = line.rfind(':')
					(file, line) = (line[:colon], line[colon+1:])
				percent = 100.0 * count / total
				if vma is None:
					print >> f, '%s,"%s",%s,%s,<unknown>,%d,%0.2f' % (modname, self.demangle(sym), file, line, count, percent)
				else:
					print >> f, '%s,"%s",%s,%s,0x%x,%d,%0.2f' % (modname, self.demangle(sym), file, line, vma, count, percent)
				
	def close(self):
		for m in self._modules.values():
			m.close()
		self._modules = {}
		self._demangler.close()
