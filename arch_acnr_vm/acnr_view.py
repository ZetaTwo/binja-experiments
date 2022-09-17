from dis import code_info
from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag, SectionSemantics

class ACNRVMView(BinaryView):
	name = 'ACNRVM22'
	long_name = 'ACNRVM 2022'

	@classmethod
	def is_valid_for_data(self, data):
		return True

	def __init__(self, data):
		BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
		self.platform = Architecture['ACNRVM'].standalone_platform
		self.data = data

	def init(self):
		code_len = min(0x1000, len(self.data))
		self.add_auto_segment(0x0, code_len, 0, code_len, SegmentFlag.SegmentReadable|SegmentFlag.SegmentWritable|SegmentFlag.SegmentExecutable)
		self.add_user_section(".text", 0x0, code_len, SectionSemantics.ReadOnlyCodeSectionSemantics)
		self.add_entry_point(0x0)
		return True

	def perform_is_executable(self):
		return True

	def perform_get_entry_point(self):
		return 0
