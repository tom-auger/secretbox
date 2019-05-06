﻿namespace SecretBox
{
    using System.Collections.Generic;
    using System.Runtime.InteropServices;

    internal static class Utilities
    {
        /// <summary>
        /// This is a hack to convert byte[] to uint[] without requiring unsafe
        /// code, or copying memory. The struct has two fields of the required
        /// types that start at the same memory location.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        internal struct ByteUintConverter
        {
            [FieldOffset(0)]
            public byte[] Bytes;

            [FieldOffset(0)]
            public uint[] Uints;
        }

        internal static void ArrayXor(
            IReadOnlyList<byte> src, int srcIdx, 
            IList<byte> dst, int dstIdx, 
            int length)
        {
            for (var i = 0; i < length; i++)
            {
                dst[i + dstIdx] ^= src[i + srcIdx];
            }
        }

        internal static void ArrayXor2(
            IReadOnlyList<byte> src1, int src1Idx, 
            IReadOnlyList<byte> src2, int src2Idx, 
            IList<byte> dst, int dstIdx, 
            int length)
        {
            for (var i = 0; i < length; i++)
            {
                dst[i + dstIdx] = (byte)(src1[i + src1Idx] ^ src2[i + src2Idx]);
            }
        }

        internal static void ArrayCopy(
            IReadOnlyList<byte> src, int srcIdx, 
            IList<byte> dst, int dstIdx, 
            int count)
        {
            for (var i = 0; i < count; i++)
            {
                dst[dstIdx + i] = src[srcIdx + i];
            }
        }

        internal static uint ArrayCompare(byte[] arr1, byte[] arr2, int length)
        {
            var arr1Converter = new ByteUintConverter { Bytes = arr1 };
            var arr1U = arr1Converter.Uints;

            var arr2Converter = new ByteUintConverter { Bytes = arr2 };
            var arr2U = arr2Converter.Uints;

            var lengthU = length / 4;
            uint cv = 0;
            for (var i = 0; i < lengthU; i++)
            {
                cv |= arr1U[i] ^ arr2U[i];
            }

            return cv;
        }
    }
}
