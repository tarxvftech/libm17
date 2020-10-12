import unittest
import libm17


class test_crc(unittest.TestCase):
    def test_spec_testvector(self):
        self.assertEqual(libm17.crc( "" ), 0xffff)
        self.assertEqual(libm17.crc( "A" ), 0x206e)
        self.assertEqual(libm17.crc( "123456789" ), 0x772B)
        b = b""
        for i in range(0,0x100):
            b += i.to_bytes(1,"big")
        self.assertEqual( libm17.crc(b), 0x1C31)
