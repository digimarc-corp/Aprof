import subprocess

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
