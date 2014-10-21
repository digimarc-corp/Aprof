import subprocess
import re
import os
import tempfile

from Module import *
from ModCache import *
from Message import *

def GetPID(appname):
	args = ['adb', 'shell', 'ps']
	p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	(outdata, errdata) = p.communicate()
	ws = re.compile('\s+')
	for fields in map(ws.split, outdata.split('\n')):
		if len(fields) >= 9 and appname == fields[8]:
			return int(fields[1])
	return -1

def GetMaps(pid):
	args = ['adb', 'shell', 'su', '-c', 'cat', '/proc/%d/maps' % pid]
	p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	(outdata, errdata) = p.communicate()
	return outdata
	
class Debugger:
	def __init__(self, localfiles, appname):
		self._appname = appname
		self._gdbserver_process = None
		self._tmpcommandfile = None
		self._pid = GetPID(self._appname)
		if self._pid < 0:
			raise Exception('No such process')
		self._modules = {}
		self._modcache = ModCache(localfiles)
		self._pull_modules()
		# Generate the add-symbol-file commands
		(fd, self._tmpcommandfile) = tempfile.mkstemp()
		os.close(fd)
		cmdfile = open(self._tmpcommandfile, 'w')
		for (modname, mod) in self._modules.items():
			localpath = self._modcache.get(modname)
			base = mod.get_base()
			offset = mod.textoffset
			if base is not None and offset is not None:
				print >> cmdfile, 'add-symbol-file %s 0x%x' % (localpath.replace('\\', '/'), base + offset)
		cmdfile.close()
		# Run gdbserver
		self._run_gdbserver()
		# Launch gdb, passing it the cmdfile
		args = ['cmd', '/k', 'start', 'arm-linux-androideabi-gdb', '-x', self._tmpcommandfile]
		self._gdb_process = subprocess.Popen(args)
		self._gdb_process.wait()
		
	def close(self):
		if self._gdbserver_process is not None:
			self._gdbserver_process.terminate()
			self._gdbserver_process.wait()
		if self._tmpcommandfile is not None:
			os.unlink(self._tmpcommandfile)
	
	def _run_gdbserver(self):
		# Ensure the port is forwarded
		os.system('adb forward tcp:9999 tcp:9999')
		# Run gdbserver
		args = ['adb', 'shell', 'su', '-c', '/data/tmp/gdbserver', '--attach', 'localhost:9999', '%d' % self._pid]
		self._gdbserver_process = subprocess.Popen(args, stdin=subprocess.PIPE)
	
	# Pull the modules from the device
	def _pull_modules(self):
		# Get process maps
		maps = GetMaps(self._pid)
		# Parse the maps
		mapre = re.compile(r'([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+(....)\s+([0-9a-fA-F]+)\s+\S+\s+\S+\s+(.+)')
		for ml in maps.split('\n'):
			mat = mapre.match(ml.strip())
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
