namespace SecretBox
{
    using System;
    using System.Diagnostics.Contracts;
    using System.Security.Cryptography;
    using System.Text;
    using static Internal.Primitive;
    using static Utilities;

    public static class SecretBox
    {
        public const int KeyBytes = 32;
        public const int ContextBytes = 8;
        public const int HeaderBytes = 20 + 16;

        private const int IVBytes = 20;
        private const int SIVBytes = 20;
        private const int MACBytes = 16;
        private static readonly byte[] Prefix = { 6, 115, 98, 120, 50, 53, 54, 8 };

        private const byte TagHeader = 0x01;
        private const byte TagPayload = 0x02;

        private static RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();

        /// <summary>
        /// Generates an encryption key.
        /// </summary>
        /// <param name="key">A buffer in which to place the generated key.</param>
        public static void GenerateKey(byte[] key)
        {
            rngCsp.GetBytes(key, 0, KeyBytes);
        }

        /// <summary>
        /// Encrypt a message with optional message Id and context, using the
        /// given key.
        /// </summary>
        /// <param name="ciphertext">A buffer in which to place the generated ciphertext.</param>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="messageLength">The length of the message to encrypt.</param>
        /// <param name="messageId">The message id.</param>
        /// <param name="context">A string of maximum 8 characters describing the context.</param>
        /// <param name="key">The encryption key.</param>
        public static void Encrypt(
            byte[] ciphertext,
            byte[] message, 
            int messageLength, 
            long messageId, 
            string context, 
            byte[] key)
        {
            var iv = new byte[IVBytes];
            rngCsp.GetBytes(iv);

            EncryptWithIv(ciphertext, message, messageLength, messageId, context, key, iv);
        }

        private static void EncryptWithIv(
            byte[] c, byte[] msg, int mlen, long msgId, string ctx, byte[] key, byte[] iv)
        {
            var buf = new byte[GimliBlockBytes];
            var m = new ArraySegment<byte>(msg, 0, mlen);
            var mac = new ArraySegment<byte>(c, SIVBytes, MACBytes);
            var ct = new ArraySegment<byte>(c, SIVBytes + MACBytes, c.Length - (SIVBytes + MACBytes));

            // If encrypting the message in place then move the message further
            // down the array to make room for the header
            if (c == msg)
            {
                Array.Copy(msg, 0, c, HeaderBytes, mlen);
                m = new ArraySegment<byte>(msg, HeaderBytes, mlen);
            }

            // First pass: compute the SIV
            Setup(buf, msgId, ctx, key, iv, GimliTagKey0);
            int i;
            for (i = 0; i < mlen / GimliRate; i++)
            {
                ArrayXor(m, i * GimliRate, buf, 0, GimliRate);
                Gimli(buf, TagPayload);
            }

            var leftOver = mlen % GimliRate;
            if (leftOver != 0)
            {
                ArrayXor(m, i * GimliRate, buf, 0, leftOver);
            }

            Pad(buf, leftOver, GimliDomainXOF);
            Gimli(buf, TagPayload);

            Finalize(buf, key, GimliTagFinal0);
            Array.Copy(buf, GimliRate, c, 0, SIVBytes);

            // Second pass: encrypt the message, mix the key, and squeeze an 
            // extra block for the MAC
            Setup(buf, msgId, ctx, key, c, GimliTagKey);
            XorEnc(buf, ct, m, mlen);

            Finalize(buf, key, GimliTagFinal);
            ArrayCopy(buf, GimliRate, mac, 0, MACBytes);
        }

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

        private static void XorEnc(
            byte[] buf, ArraySegment<byte> output, ArraySegment<byte> input, int inputLength)
        {
            int i;
            for (i = 0; i < inputLength / GimliRate; i++)
            {
                ArrayXor2(input, i * GimliRate, buf, 0, output, i * GimliRate, GimliRate);
                ArrayCopy(output, i * GimliRate, buf, 0, GimliRate);
                Gimli(buf, TagPayload);
            }

            var leftOver = inputLength % GimliRate;
            if (leftOver != 0)
            {
                ArrayXor2(input, i * GimliRate, buf, 0, output, i * GimliRate, leftOver);
                ArrayCopy(output, i * GimliRate, buf, 0, leftOver);
            }

            Pad(buf, leftOver, GimliDomainAEAD);
            Gimli(buf, TagPayload);
        }

        private static void Finalize(byte[] buf, byte[] key, byte tag)
        {
            Contract.Assert(KeyBytes == GimliCapacity);
            ArrayXor(key, 0, buf, GimliRate, KeyBytes);
            Gimli(buf, tag);
            ArrayXor(key, 0, buf, GimliRate, KeyBytes);
            Gimli(buf, tag);
        }

        private static void Pad(byte[] buf, int position, byte domain)
        {
            buf[position] ^= (byte)((domain << 1) | 1);
            buf[GimliRate - 1] ^= 0x80;
        }
    }
}
