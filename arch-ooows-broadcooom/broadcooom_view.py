from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag

class BroadcooomView(BinaryView):
	name = 'Broadcooom'
	long_name = 'Broadcooom'

	@classmethod
	def is_valid_for_data(self, data):
		return len(data) % 5 == 0

	def __init__(self, data):
		BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
		self.platform = Architecture['Broadcooom'].standalone_platform
		self.data = data

	def init(self):
		self.add_auto_segment(0, 0x4000, 0, 0x4000, SegmentFlag.SegmentReadable|SegmentFlag.SegmentWritable|SegmentFlag.SegmentExecutable)		
		self.add_entry_point(0)
		return True

	def perform_is_executable(self):
		return True

	def perform_get_entry_point(self):
		return 0
