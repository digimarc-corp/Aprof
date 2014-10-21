class HitCounter:
	def __init__(self):
		self._count = {}
		
	def hit(self, key):
		self._count[key] = self._count.get(key, 0) + 1

	def get_hits(self):
		return [(count, key) for key, count in self._count.items()]
