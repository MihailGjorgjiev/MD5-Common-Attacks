import struct


class SimpleMD5:
    def __init__(self):
        self._initialize_state()

    def _initialize_state(self):
        self.state = [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210]

    def _left_rotate(self, x, c):
        return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

    def _F(self, x, y, z):
        return (x & y) | (~x & z)

    def _G(self, x, y, z):
        return (x & z) | (y & ~z)

    def _H(self, x, y, z):
        return x ^ y ^ z

    def _I(self, x, y, z):
        return y ^ (x | ~z)

    def _FF(self, a, b, c, d, x, s, ac):
        a = (a + self._F(b, c, d) + x + ac) & 0xFFFFFFFF
        a = self._left_rotate(a, s)
        return (a + b) & 0xFFFFFFFF

    def _GG(self, a, b, c, d, x, s, ac):
        a = (a + self._G(b, c, d) + x + ac) & 0xFFFFFFFF
        a = self._left_rotate(a, s)
        return (a + b) & 0xFFFFFFFF

    def _HH(self, a, b, c, d, x, s, ac):
        a = (a + self._H(b, c, d) + x + ac) & 0xFFFFFFFF
        a = self._left_rotate(a, s)
        return (a + b) & 0xFFFFFFFF

    def _II(self, a, b, c, d, x, s, ac):
        a = (a + self._I(b, c, d) + x + ac) & 0xFFFFFFFF
        a = self._left_rotate(a, s)
        return (a + b) & 0xFFFFFFFF

    def _process_block(self, block):
        a, b, c, d = self.state

        a = self._FF(a, b, c, d, block[0], 7, 0xD76AA478)
        d = self._FF(d, a, b, c, block[1], 12, 0xE8C7B756)
        c = self._FF(c, d, a, b, block[2], 17, 0x242070DB)
        b = self._FF(b, c, d, a, block[3], 22, 0xC1BDCEEE)

        a = self._FF(a, b, c, d, block[4], 7, 0xF57C0FAF)
        d = self._FF(d, a, b, c, block[5], 12, 0x4787C62A)
        c = self._FF(c, d, a, b, block[6], 17, 0xA8304613)
        b = self._FF(b, c, d, a, block[7], 22, 0xFD469501)

        a = self._FF(a, b, c, d, block[8], 7, 0x698098D8)
        d = self._FF(d, a, b, c, block[9], 12, 0x8B44F7AF)
        c = self._FF(c, d, a, b, block[10], 17, 0xFFFF5BB1)
        b = self._FF(b, c, d, a, block[11], 22, 0x895CD7BE)

        a = self._FF(a, b, c, d, block[12], 7, 0x6B901122)
        d = self._FF(d, a, b, c, block[13], 12, 0xFD987193)
        c = self._FF(c, d, a, b, block[14], 17, 0xA679438E)
        b = self._FF(b, c, d, a, block[15], 22, 0x49B40821)

        self.state = [(a + self.state[0]) & 0xFFFFFFFF,
                      (b + self.state[1]) & 0xFFFFFFFF,
                      (c + self.state[2]) & 0xFFFFFFFF,
                      (d + self.state[3]) & 0xFFFFFFFF]

    def _md5_padding(self, message_len):
        padding = b'\x80'
        padding += b'\x00' * ((56 - (message_len + 1) % 64) % 64)
        padding += struct.pack('<Q', message_len * 8)
        return padding

    def update(self, message):

        self._initialize_state()

        if isinstance(message, str):
            message = message.encode('utf-8')

        message_len = len(message)
        message_padding = self._md5_padding(message_len)
        message += message_padding

        for i in range(0, len(message), 64):
            block = [int.from_bytes(message[i + j:i + j + 4], 'little') for j in range(0, 64, 4)]

            self._process_block(block)

    def finalize(self):
        return struct.pack('<I', self.state[0])

    def hash(self, message):
        self.update(message)
        return self.finalize()
