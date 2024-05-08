using System;
using System.IO;

namespace libusb_tester
{
    class NSRecord
    {
        static byte HexVal(char c)
        {
            switch (c)
            {
                case '0': return 0;
                case '1': return 1;
                case '2': return 2;
                case '3': return 3;
                case '4': return 4;
                case '5': return 5;
                case '6': return 6;
                case '7': return 7;
                case '8': return 8;
                case '9': return 9;
                case 'A':
                case 'a': return 10;
                case 'B':
                case 'b': return 11;
                case 'C':
                case 'c': return 12;
                case 'D':
                case 'd': return 13;
                case 'E':
                case 'e': return 14;
                case 'F':
                case 'f': return 15;
                default: throw new Exception("Invalid hex character");
            }
        }
        static MemoryStream FromString(string s)
        {
            var st = new MemoryStream();
            for (int i = 0; i < s.Length - 1; i += 2)
            {
                var b = HexVal(s[i]);
                b <<= 4;
                b |= HexVal(s[i + 1]);
                st.WriteByte(b);
            }
            st.Seek(0, SeekOrigin.Begin);
            return st;
        }
        static byte ReadByte(Stream st, string s)
        {
            var n = st.ReadByte();
            if (n < 0)
                throw new Exception($"End of stream reached while reading {s}");
            return (byte)n;
        }
        public NSRecord(string s)
        {
            var st = FromString(s);
            var b = ReadByte(st, "initial tag byte");
            var taglen = 1;
            Console.WriteLine($"Read tag byte {taglen}: {b:X2}");
            ulong tag = 0;
            if ((b & 0x1f) == 0x1f)
            {
                do
                {
                    b = ReadByte(st, $"high tag byte {taglen}");
                    taglen++;
                    Console.WriteLine($"Read tag byte {taglen}: {b:X2}");
                    if (taglen > 10)
                        throw new Exception("Too long tag");
                    var bb = (byte)(b & 0x7f);
                    Console.WriteLine($"Masked {bb:X2}");
                    tag <<= 7;
                    tag |= bb;
                    Console.WriteLine($"High Tag {tag:X16}");
                } while ((b & 0x80) != 0);
            }
            else
            {
                tag = b;
                Console.WriteLine($"Low valued Tag {tag:X16}");
            }
            ulong len = 0;
            b = ReadByte(st, "initial length byte");
            Console.WriteLine($"Read {b:X2}");
            if (b < 0x80)
            {
                len = b;
                Console.WriteLine($"Len {len:X16}");
            }
            else
            {
                var lenlen = (byte)(b & 0x7f);
                Console.WriteLine($"Length of length {lenlen}");
                if (lenlen < 1 || lenlen > 8)
                    throw new Exception($"Invalid length of length {lenlen}");
                while (lenlen > 0)
                {
                    b = ReadByte(st, "additional length bytes");
                    Console.WriteLine($"Read {b:X2}");
                    len <<= 8;
                    len |= b;
                    Console.WriteLine($"Len {len:X16}");
                    lenlen--;
                }
            }
            var buf = new byte[len];
            var actual = st.Read(buf);
            if ((ulong)actual != len)
                throw new Exception("Failed to read data");
            Console.WriteLine($"{actual:X} bytes data read");
        }
    }
}
