namespace SecretBox
{
    using System.Collections.Generic;

    internal static class Utilities
    {
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
    }
}
