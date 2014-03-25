import struct
import string

caps = string.letters[26:]
lower = string.letters[:26]

registers = ["gs", "fs", "es", "ds", "edi", "esi", "ebp", "esp", "ebx", "edx", "ecx", "eax", "JUNK", "JUNK", "eip", "cs", "eflags"]
reg_pos_mapping = {}
for pos, reg in enumerate(registers):
    reg_pos_mapping[reg] = pos

class SigreturnFrame(object):
    def __init__(self, arch="x86", sane=True, nulls_allowed=False):
        self.arch  = arch
        self.frame = []
        self.sane  = sane
        self.nulls_allowed = nulls_allowed
        self.initialize_vals()

    def initialize_vals(self):
        if self.arch == "x86":
            for i in caps + lower:
                self.frame.append(i * 4)
            if self.sane:
                self.set_regvalue("gs", 0x33)
		if self.nulls_allowed:
                    self.set_regvalue("fs", 0x0)
                self.set_regvalue("es", 0x7b)
                self.set_regvalue("ds", 0x7b)
                self.set_regvalue("cs", 0x73)
                self.set_regvalue("eflags", 0x246)

    def set_regvalue(self, reg, val):
        index = reg_pos_mapping[reg]
        self.frame[index] = struct.pack("<I", val)

    def get_frame(self):
        return ''.join(self.frame)	
