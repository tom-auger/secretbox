namespace SecretBox
{
    using System;
    using System.Diagnostics.Contracts;
    using System.Security.Cryptography;
    using System.Text;
    using static Internal.Primitive;
    using static Utilities;

    public class SecretBox : ISecretBox
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
        /// <param name="key">The buffer in which to place the generated key.</param>
        public void GenerateKey(byte[] key)
        {
            rngCsp.GetBytes(key, 0, KeyBytes);
        }

        /// <summary>
        /// Encrypt a message using the given key, with context and optional message ID.
        /// </summary>
        /// <param name="ciphertext">A buffer in which to place the generated ciphertext.</param>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="messageLength">The length of the message to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="context">A string of maximum 8 characters describing the context.</param>
        /// <param name="messageId">Optional message ID. Defaults to 1.</param>
        public void Encrypt(
            byte[] ciphertext,
            byte[] message,
            int messageLength,
            byte[] key,
            string context,
            long messageId = 1)
        {
            ValidateEncryptionParameters(ciphertext, message, messageLength, key, context);

            var iv = GenerateIV();
            var ctx = ConvertContextToBytes(context);
            EncryptWithIv(ciphertext, message, messageLength, key, iv, ctx, messageId);
        }

        /// <summary>
        /// Decrypt a ciphertext using the given key, with context and optional message ID.
        /// </summary>
        /// <param name="message">A buffer in which to place the decrypted message.</param>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="ciphertextLength">The length of the ciphertext to decrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="context">A string of maximum 8 characters describing the context.</param>
        /// <param name="messageId">Optional message ID. Defaults to 1.</param>
        public void Decrypt(
            byte[] message,
            byte[] ciphertext, 
            int ciphertextLength,
            byte[] key,
            string context,
            long messageId = 1)
        {
            ValidateDecryptionParameters(message, ciphertext, ciphertextLength, key, context);

            var buf = new byte[GimliBlockBytes];
            var ctx = ConvertContextToBytes(context);
            var ct = new ArraySegment<byte>(
                ciphertext,
                SIVBytes + MACBytes, 
                ciphertext.Length - (SIVBytes + MACBytes));

            var mlen = ciphertextLength - HeaderBytes;
            // Store the MAC to compare against the value computed from the decryption later
            var pubMac = new byte[MACBytes];
            Array.Copy(ciphertext, SIVBytes, pubMac, 0, MACBytes);

            // Decrypt the message
            Setup(buf, messageId, ctx, key, ciphertext, GimliTagKey);
            XorDec(buf, ct, mlen, message);
            Finalize(buf, key, GimliTagFinal);

            // Compare the MAC from the decrypted message with the MAC included in 
            // the ciphertext header
            var cv = ComputeChecksum(buf, pubMac);
            Array.Clear(buf, 0, GimliBlockBytes);
            if (cv != 0)
            {
                // If the MAC is invalid then throw away any decryption result and error out
                Array.Clear(message, 0, mlen);
                throw new CryptographicException("MAC check failed.");
            }
        }

        private static void EncryptWithIv(
            byte[] c, byte[] m, int mlen, byte[] key, byte[] iv, byte[] ctx, long msgId)
        {
            var buf = new byte[GimliBlockBytes];
            var msg = new ArraySegment<byte>(m, 0, mlen);
            var mac = new ArraySegment<byte>(c, SIVBytes, MACBytes);
            var ct = new ArraySegment<byte>(
                c,
                SIVBytes + MACBytes, 
                c.Length - (SIVBytes + MACBytes));

            // If encrypting the message in place then move the message further
            // down the array to make room for the header
            if (c == m)
            {
                Array.Copy(m, 0, c, HeaderBytes, mlen);
                msg = new ArraySegment<byte>(m, HeaderBytes, mlen);
            }

            // First pass: compute the SIV
            Setup(buf, msgId, ctx, key, iv, GimliTagKey0);
            int i;
            for (i = 0; i < mlen / GimliRate; i++)
            {
                ArrayXor(msg, i * GimliRate, buf, 0, GimliRate);
                Gimli(buf, TagPayload);
            }

            var leftOver = mlen % GimliRate;
            if (leftOver != 0)
            {
                ArrayXor(msg, i * GimliRate, buf, 0, leftOver);
            }

            Pad(buf, leftOver, GimliDomainXOF);
            Gimli(buf, TagPayload);

            Finalize(buf, key, GimliTagFinal0);
            Array.Copy(buf, GimliRate, c, 0, SIVBytes);

            // Second pass: encrypt the message, mix the key, and squeeze an 
            // extra block for the MAC
            Setup(buf, msgId, ctx, key, c, GimliTagKey);
            XorEnc(buf, msg, mlen, ct);

            Finalize(buf, key, GimliTagFinal);
            ArrayCopy(buf, GimliRate, mac, 0, MACBytes);
        }

        private static void Setup(
            byte[] buf, long msgId, byte[] ctx, byte[] key, byte[] iv, byte keyTag)
        {
            Contract.Assert(buf.Length == GimliBlockBytes);
            Contract.Assert(ctx.Length == ContextBytes);

            // Zero out the buffer
            Array.Clear(buf, 0, GimliBlockBytes);

            // Add the prefix and context and apply the Gimli permutation
            Array.Copy(Prefix, buf, Prefix.Length);
            Array.Copy(ctx, 0, buf, Prefix.Length, ContextBytes);
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
            byte[] buf, ArraySegment<byte> input, int inputLength, ArraySegment<byte> output)
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

        private static void XorDec(
            byte[] buf, ArraySegment<byte> input, int inputLength, byte[] output)
        {
            int i;
            for (i = 0; i < inputLength / GimliRate; i++)
            {
                ArrayXor2(input, i * GimliRate, buf, 0, output, i * GimliRate, GimliRate);
                ArrayCopy(input, i * GimliRate, buf, 0, GimliRate);
                Gimli(buf, TagPayload);
            }

            var leftOver = inputLength % GimliRate;
            if (leftOver != 0)
            {
                ArrayXor2(input, i * GimliRate, buf, 0, output, i * GimliRate, leftOver);
                ArrayCopy(input, i * GimliRate, buf, 0, leftOver);
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

        private static uint ComputeChecksum(byte[] buf, byte[] pubMac)
        {
            // Convert the byte arrays to uint arrays
            var bufConverter = new ByteUintConverter { Bytes = buf };
            var bufU = bufConverter.Uints;

            var pubMacConverter = new ByteUintConverter { Bytes = pubMac };
            var pubMacU = pubMacConverter.Uints;

            // Compare the MAC calculated from the decrypted ciphertext with the public MAC,
            // which was included in the ciphertext header.
            return ArrayCompare(bufU, GimliRate / 4, pubMacU, 0, MACBytes / 4);
        }

        private static byte[] GenerateIV()
        {
            var iv = new byte[IVBytes];
            rngCsp.GetBytes(iv);
            return iv;
        }

        private static byte[] ConvertContextToBytes(string context)
        {
            var ctx = new byte[ContextBytes];
            Encoding.UTF8.GetBytes(context, 0, context.Length, ctx, 0);
            return ctx;
        }

        private static void ValidateDecryptionParameters(
            byte[] message,
            byte[] ciphertext,
            int ciphertextLength,
            byte[] key,
            string context)
        {
            ValidateKeyAndContext(key, context);

            if (ciphertext.Length < ciphertextLength)
            {
                throw new ArgumentException(
                    $"'{nameof(ciphertextLength)}' must be at most the length of '{nameof(ciphertext)}'");
            }

            if (message.Length < ciphertextLength - HeaderBytes)
            {
                throw new ArgumentException(
                    $"'{nameof(message)}' length must be at least {nameof(ciphertextLength)} - {nameof(HeaderBytes)}");
            }
        }

        private static void ValidateEncryptionParameters(
            byte[] ciphertext,
            byte[] message,
            int messageLength,
            byte[] key,
            string context)
        {
            ValidateKeyAndContext(key, context);

            if (message.Length < messageLength)
            {
                throw new ArgumentException(
                    $"'{nameof(messageLength)}' must be at most the length of '{nameof(message)}'");
            }

            if (ciphertext.Length < messageLength + HeaderBytes)
            {
                throw new ArgumentException(
                    $"'{nameof(ciphertext)}' length must be at least {nameof(messageLength)} + {nameof(HeaderBytes)}");
            }
        }

        private static void ValidateKeyAndContext(byte[] key, string context)
        {
            if (key.Length != KeyBytes)
            {
                throw new ArgumentException($"'{nameof(key)}' length must be {KeyBytes} bytes");
            }

            if (context.Length > ContextBytes)
            {
                throw new ArgumentException($"'{nameof(context)}' must be at most {ContextBytes} characters");
            }
        }
    }
}
