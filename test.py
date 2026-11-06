from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])


def enc_ae(d, k, iv):
    return AES.new(k, AES.MODE_CBC, iv).encrypt(pad(d, 16))


def dec_ae(d, k, iv):
    try:
        return unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(d), 16)
    except Exception:
        return None


class Codec:
    @staticmethod
    def vi(n):
        if n < 0:
            n = (1 << 64) + n
        o = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            if n:
                b |= 0x80
            o.append(b)
            if not n:
                break
        return bytes(o)

    @staticmethod
    def rv(bl, i):
        r = 0
        s = 0
        while i < len(bl):
            b = bl[i]
            i += 1
            r |= (b & 0x7F) << s
            if not (b & 0x80):
                break
            s += 7
        return r, i

    @staticmethod
    def enc(fields):
        b = bytearray()
        for k, v in fields.items():
            if isinstance(v, bool):
                b += Codec.vi((k << 3) | 0) + Codec.vi(int(v))
            elif isinstance(v, int):
                b += Codec.vi((k << 3) | 0) + Codec.vi(v)
            elif isinstance(v, str):
                d = v.encode()
                b += Codec.vi((k << 3) | 2) + Codec.vi(len(d)) + d
            elif isinstance(v, (bytes, bytearray)):
                d = bytes(v)
                b += Codec.vi((k << 3) | 2) + Codec.vi(len(d)) + d
        return bytes(b)

    @staticmethod
    def dec(bl):
        f = {}
        i = 0
        n = len(bl)
        while i < n:
            try:
                k, i = Codec.rv(bl, i)
            except Exception:
                break
            if k == 0:
                i += 1
                continue
            fn, wt = k >> 3, k & 7
            try:
                if wt == 0:
                    v, i = Codec.rv(bl, i)
                elif wt == 2:
                    ln, i = Codec.rv(bl, i)
                    if ln < 0 or i + ln > n:
                        break
                    v = bl[i:i + ln]
                    i += ln
                elif wt == 5:
                    if i + 4 > n:
                        break
                    v = bl[i:i + 4]
                    i += 4
                elif wt == 1:
                    if i + 8 > n:
                        break
                    v = bl[i:i + 8]
                    i += 8
                else:
                    i += 1
                    continue
            except Exception:
                i += 1
                continue
            f.setdefault(fn, []).append(v)
        return f