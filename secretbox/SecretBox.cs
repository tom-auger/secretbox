﻿namespace SecretBox
{
    using System;
    using System.Diagnostics.Contracts;
    using System.Text;
    using static Internal.Primitive;

    public static class SecretBox
    {
        public const int KeyBytes = 32;
        public const int ContextBytes = 8;

        private const int IVBytes = 20;
        private static readonly byte[] Prefix = { 6, 115, 98, 120, 50, 53, 54, 8 };

        private const byte TagHeader = 0x01;
        private const byte TagPayload = 0x02;

        private static void Setup(byte[] buf, long msgId, string ctx, byte[] key, byte[] iv, byte keyTag)
        {
            Contract.Assert(buf.Length == GimliBlockBytes);
            Contract.Assert(ctx.Length == ContextBytes);

            // Zero out the buffer
            Array.Clear(buf, 0, GimliBlockBytes);

            // Add the prefix and context and apply the Gimli permutation
            Array.Copy(Prefix, buf, Prefix.Length);
            // TODO: Change the interface of this method to have ctx a byte array and 
            // do the conversion in the calling function
            var ctxBytes = Encoding.UTF8.GetBytes(ctx);
            Array.Copy(ctxBytes, 0, buf, Prefix.Length, ContextBytes);
            Contract.Assert(Prefix.Length + ContextBytes == GimliRate);
            Gimli(buf, TagHeader);

            // Add the key and apply the Gimli permutation
            Contract.Assert(KeyBytes == 2 * GimliRate);
            ArrayXor(key, 0, buf, 0, GimliRate);
            Gimli(buf, keyTag);
            ArrayXor(key, GimliRate, buf, 0, GimliRate);
            Gimli(buf, keyTag);

            // Add the IV and apply the Gimli permutation
            Contract.Assert(IVBytes < GimliRate * 2);
            buf[0] ^= IVBytes;
            ArrayXor(iv, 0, buf, 1, GimliRate - 1);
            Gimli(buf, TagHeader);
            ArrayXor(iv, GimliRate - 1, buf, 0, IVBytes - (GimliRate - 1));

            // Add the msgId and apply the Gimli permutation.
            // Convert the int64 msgId to an array of 8 bytes
            Contract.Assert(IVBytes - GimliRate + 8 <= GimliRate);
            var msgIdBytes = BitConverter.GetBytes(msgId);
            ArrayXor(msgIdBytes, 0, buf, IVBytes - GimliRate, 8);
            Gimli(buf, TagHeader);
        }

        private static void Finalize(byte[] buf, byte[] key, byte tag)
        {
            Contract.Assert(KeyBytes == GimliCapacity);
            ArrayXor(key, 0, buf, GimliRate, KeyBytes);
            Gimli(buf, tag);
            ArrayXor(key, 0, buf, GimliRate, KeyBytes);
            Gimli(buf, tag);
        }

        private static void XorEnc(byte[] buf, byte[] output, byte[] input, int inputLength)
        {
            // TODO: May want to make i a bigger type, e.g. long or add overlaods (generic with type restriction?)
            int i;
            for (i = 0; i < inputLength / GimliRate; i++)
            {
                ArrayXor2(input, i * GimliRate, buf, 0, output, i * GimliRate, GimliRate);
                Array.Copy(output, i * GimliRate, buf, 0, GimliRate);
                Gimli(buf, TagPayload);
            }

            var leftOver = inputLength % GimliRate;
            if (leftOver != 0)
            {
                ArrayXor2(input, i * GimliRate, buf, 0, output, i * GimliRate, leftOver);
                Array.Copy(output, i * GimliRate, buf, 0, leftOver);
            }

            Pad(buf, leftOver, GimliDomainAEAD);
            Gimli(buf, TagPayload);
        }

        private static void Pad(byte[] buf, int pos, byte domain)
        {
            buf[pos] ^= (byte)((domain << 1) | 1);
            buf[GimliRate - 1] ^= 0x80;
        }

        private static void ArrayXor(byte[] src, int srcIdx, byte[] dst, int dstIdx, int length)
        {
            for (var i = 0; i < length; i++)
            {
                dst[i + dstIdx] ^= src[i + srcIdx];
            }
        }

        private static void ArrayXor2(byte[] src1, int src1Idx, byte[] src2, int src2Idx, byte[] dst, int dstIdx, int length)
        {
            for (var i = 0; i < length; i++)
            {
                dst[i + dstIdx] = (byte)(src1[i + src1Idx] ^ src2[i + src2Idx]);
            }
        }
    }
}
