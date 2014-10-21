import subprocess

from Message import *

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
