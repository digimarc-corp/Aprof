import re
import subprocess

from Message import *

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
				symsize = int(fields[2], 0)
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
