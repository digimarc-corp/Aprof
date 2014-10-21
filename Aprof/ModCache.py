import os
import subprocess

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
