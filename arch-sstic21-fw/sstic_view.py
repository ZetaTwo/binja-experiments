from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag

class SSTICView(BinaryView):
	name = 'SSTIC21'
	long_name = 'SSTIC 2021'

	@classmethod
	def is_valid_for_data(self, data):
		return True

	def __init__(self, data):
		BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
		self.platform = Architecture['SSTIC3'].standalone_platform
		self.data = data

	def init(self):
		self.add_auto_segment(0x1000, 0x4000, 0, 0x4000, SegmentFlag.SegmentReadable|SegmentFlag.SegmentWritable|SegmentFlag.SegmentExecutable)		
		self.add_entry_point(0x1000)
		return True

	def perform_is_executable(self):
		return True

	def perform_get_entry_point(self):
		return 0
