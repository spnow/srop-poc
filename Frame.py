import struct
import string

caps = string.letters[26:]
lower = string.letters[:26]

registers = ["gs",   "fs",  "es",  "ds",   "edi",  "esi", "ebp", "esp", "ebx",
             "edx",  "ecx", "eax", "JUNK", "JUNK", "eip", "cs",  "eflags",
             "JUNK", "ss",  "floa"]

reg_pos_mapping = {}
for pos, reg in enumerate(registers):
    reg_pos_mapping[reg] = pos

class ValueException(Exception):
    def __init__(self, register, value):
        self.value = value
    def __str__(self):
        return "Register: %s Value: %d" %(register, value)

class SigreturnFrame(object):
    def __init__(self, arch="x86"):
        self.arch  = arch
        self.frame = []
        self.initialize_vals()

    def initialize_vals(self):
        if self.arch == "x86":
            self._initialize_x86()

    def _initialize_x86(self):
        for i in range(len(registers)):
            self.frame.append(struct.pack("<I", 0x0))

    def set_regvalue(self, reg, val):
        if self.arch == "x86":
            self._set_regvalue_x86(reg, val)

    def _set_regvalue_x86(self, reg, val):
        index = reg_pos_mapping[reg]
        value = struct.pack("<I", val)
        if reg == "ss":
            value = struct.pack("<h", val) + "\x00\x00"
        self.frame[index] = value

    def get_frame(self):
        frame_contents = ''.join(self.frame)
        assert len(frame_contents) == len(registers) * 4
        return frame_contents
