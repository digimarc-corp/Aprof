import re
import subprocess

from SymbolResolver import *
from LineResolver import *
from Message import *

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
		# Get the offset of the .text segment. We need this to calculate the
		# correct load address to pass to gdb add-symbol-file.
		p = subprocess.Popen(['arm-linux-androideabi-readelf', '-S', '-W', localpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(out, errout) = p.communicate()
		if p.returncode:
			Warning('Module %s is not a valid ELF file' % self._remotepath)
			return
		textre = re.compile('.*]\s+(\S+)\s+\S+\s+\S+\s+(\S+).*')
		self.textoffset = None
		for sl in out.split('\n'):
			mat = textre.match(sl)
			if mat and mat.group(1) == '.text':
				self.textoffset = int(mat.group(2), 16)
				break
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
	
	def get_base(self):
		base = None
		if len(self._mappings) > 0:
			base = self._mappings[0][0]
			for m in self._mappings[1:]:
				if m[0] < base:
					base = m[0]
		return base
	
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
