namespace Tests
{
    using NUnit.Framework;
    using SecretBox;
    using System;
    using System.Security.Cryptography;
    using System.Text;
    using static SecretBox.SecretBox;

    public class SecretBoxTests
    {
        [TestCase(12, Description = "Key too short")]
        [TestCase(44, Description = "Key too long")]
        public void Encrypt_ValidateKeyLength(int keyLength)
        {
            var sb = new SecretBox();
            var key = new byte[keyLength];
            const int mlen = 12;
            var m = new byte[mlen];
            var c = new byte[sb.CalculateCiphertextLength(mlen)];
            var ctx = "test";

            Assert.That(
                () => sb.Encrypt(c, m, mlen, key, ctx), 
                Throws.ArgumentException.With.Message.EqualTo(
                    $"'key' length must be {KeyBytes} bytes"));
        }

        [Test]
        public void Encrypt_ValidateMessageLength_TooLong()
        {
            var sb = new SecretBox();
            var key = new byte[KeyBytes];
            const int mlen = 44;
            const int mlenActual = 12;
            var m = new byte[mlenActual];
            var c = new byte[sb.CalculateCiphertextLength(mlenActual)];
            var ctx = "test";

            Assert.That(
                () => sb.Encrypt(c, m, mlen, key, ctx),
                Throws.ArgumentException.With.Message.EqualTo(
                    $"'messageLength' must be at most the length of 'message'"));
        }

        [Test]
        public void Encrypt_ValidateContextLength_TooLong()
        {
            var sb = new SecretBox();
            var key = new byte[KeyBytes];
            const int mlen = 12;
            var m = new byte[mlen];
            var c = new byte[sb.CalculateCiphertextLength(mlen)];
            var ctx = "you are old father william";

            Assert.That(
                () => sb.Encrypt(c, m, mlen, key, ctx),
                Throws.ArgumentException.With.Message.EqualTo(
                    $"'context' must be at most {ContextBytes} characters"));
        }

        [Test]
        public void Encrypt_ValidateCiphertextLength_TooShort()
        {
            var key = new byte[KeyBytes];
            const int mlen = 12;
            var m = new byte[mlen];
            var c = new byte[mlen];
            var ctx = "test";

            var sb = new SecretBox();
            Assert.That(
                () => sb.Encrypt(c, m, mlen, key, ctx),
                Throws.ArgumentException.With.Message.EqualTo(
                    $"'ciphertext' length must be at least messageLength + {nameof(HeaderBytes)}"));
        }

        [TestCase(12, Description = "Key too short")]
        [TestCase(44, Description = "Key too long")]
        public void Decrypt_ValidateKeyLength(int keyLength)
        {
            var sb = new SecretBox();
            var key = new byte[keyLength];
            const int clen = 100;
            var c = new byte[clen];
            var m = new byte[sb.CalculateMessageLength(clen)];
            var ctx = "test";

            Assert.That(
                () => sb.Decrypt(m, c, clen, key, ctx),
                Throws.ArgumentException.With.Message.EqualTo(
                    $"'key' length must be {KeyBytes} bytes"));
        }

        [Test]
        public void Decrypt_ValidateCiphertextLength_TooLong()
        {
            var sb = new SecretBox();
            var key = new byte[KeyBytes];
            const int clen = 200;
            const int clenActual = 100;
            var c = new byte[clenActual];
            var m = new byte[sb.CalculateMessageLength(clenActual)];
            var ctx = "test";

            Assert.That(
                () => sb.Decrypt(m, c, clen, key, ctx),
                Throws.ArgumentException.With.Message.EqualTo(
                    $"'ciphertextLength' must be at most the length of 'ciphertext'"));
        }

        [Test]
        public void Decrypt_ValidatesCiphertextLength_TooShort()
        {
            var sb = new SecretBox();
            var key = new byte[KeyBytes];
            const int clen = 1;
            const int clenActual = 100;
            var c = new byte[clenActual];
            var m = new byte[sb.CalculateMessageLength(clenActual)];
            var ctx = "test";

            Assert.That(
                () => sb.Decrypt(m, c, clen, key, ctx),
                Throws.ArgumentException.With.Message.EqualTo(
                    $"'ciphertextLength' must be at least 'HeaderBytes'"));
        }

        [Test]
        public void Decrypt_ValidateContextLength_TooLong()
        {
            var sb = new SecretBox();
            var key = new byte[KeyBytes];
            const int clen = 100;
            var c = new byte[clen];
            var m = new byte[sb.CalculateMessageLength(clen)];
            var ctx = "you are old father william";

            Assert.That(
                () => sb.Decrypt(m, c, clen, key, ctx),
                Throws.ArgumentException.With.Message.EqualTo(
                    $"'context' must be at most {ContextBytes} characters"));
        }

        [Test]
        public void Decrypt_ValidateMessageLength_TooShort()
        {
            var key = new byte[KeyBytes];
            const int clen = 100;
            var c = new byte[clen];
            var m = new byte[10];
            var ctx = "test";

            var sb = new SecretBox();
            Assert.That(
                () => sb.Decrypt(m, c, clen, key, ctx),
                Throws.ArgumentException.With.Message.EqualTo(
                    $"'message' length must be at least ciphertextLength - {nameof(HeaderBytes)}"));
        }

        [Test]
        public void CalculateCipherTextLength()
        {
            const int messageLength = 10;
            const int expectedLength = messageLength + HeaderBytes;
            var sb = new SecretBox();
            Assert.That(sb.CalculateCiphertextLength(messageLength), Is.EqualTo(expectedLength));
        }

        [Test]
        public void CalculateCipherTextLength_LessThanZero()
        {
            var sb = new SecretBox();
            Assert.That(
                () => sb.CalculateCiphertextLength(-3), 
                Throws.ArgumentException.With.Message.EqualTo(
                    "messageLength must be greater than 0"));
        }

        [Test]
        public void CalculateMessageLength()
        {
            const int ciphertextLength = 80;
            const int expectedLength = ciphertextLength - HeaderBytes;
            var sb = new SecretBox();
            Assert.That(sb.CalculateMessageLength(ciphertextLength), Is.EqualTo(expectedLength));
        }

        [TestCase(-3, Description = "Less than zero")]
        [TestCase(7, Description = "Less than HeaderBytes")]
        public void CalculateMessageLength_Invalid(int ciphertextLength)
        {
            var sb = new SecretBox();
            Assert.That(
                () => sb.CalculateMessageLength(ciphertextLength),
                Throws.ArgumentException.With.Message.EqualTo(
                    $"ciphertextLength must be greater than {nameof(HeaderBytes)}"));
        }

        [Test]
        public void VerifyMessageCanBeEncryptedAndDecrypted()
        {
            var sb = new SecretBox();

            // Generate a key
            var key = new byte[KeyBytes];
            sb.GenerateKey(key);

            // Generate a message to encrypt
            var message = Encoding.UTF8.GetBytes("You are old Father William, the young man said");
            const int messageId = 1;
            const string context = "test";

            // Buffer to hold the ciphertext
            var ciphertext = new byte[sb.CalculateCiphertextLength(message.Length)];

            // Encrypt
            sb.Encrypt(ciphertext, message, message.Length, key, context, messageId);

            // Buffer to hold decrypted message
            var decryptedMessage = new byte[message.Length];

            // Decrypt
            sb.Decrypt(decryptedMessage, ciphertext, ciphertext.Length, key, context, messageId);

            // Verify the decrypted message
            Assert.That(decryptedMessage, Is.EqualTo(message));

            // Decrypt using TryDecrypt
            Array.Clear(decryptedMessage, 0, decryptedMessage.Length);
            var result = sb.TryDecrypt(decryptedMessage, ciphertext, ciphertext.Length, key, context, messageId);

            // Verify the decrypted message
            Assert.That(decryptedMessage, Is.EqualTo(message));
            Assert.That(result, Is.True);
        }

        [Test]
        public void VerifyDecryptFailsWithInvalidParameters()
        {
            var sb = new SecretBox();

            // Generate an encrypted message
            var key = new byte[KeyBytes];
            sb.GenerateKey(key);
            var message = Encoding.UTF8.GetBytes("You are old Father William, the young man said");
            const int messageId = 1;
            const string context = "test";
            var ciphertext = new byte[sb.CalculateCiphertextLength(message.Length)];
            sb.Encrypt(ciphertext, message, message.Length, key, context, messageId);

            // Buffer to hold decrypted message
            var decryptedMessage = new byte[message.Length];

            // Verify error when ciphertextLength is incorrect
            Assert.That(
                () => sb.Decrypt(decryptedMessage, ciphertext, HeaderBytes, key, context, messageId), 
                Throws.TypeOf<CryptographicException>().With.Message.EqualTo("MAC check failed"));
            Assert.That(
                sb.TryDecrypt(decryptedMessage, ciphertext, HeaderBytes, key, context, messageId),
                Is.False);

            // Verify error when the message id is incorrect
            Assert.That(
                () => sb.Decrypt(decryptedMessage, ciphertext, ciphertext.Length, key, context, 2),
                Throws.TypeOf<CryptographicException>().With.Message.EqualTo("MAC check failed"));
            Assert.That(
                sb.TryDecrypt(decryptedMessage, ciphertext, ciphertext.Length, key, context, 2),
                Is.False);

            // Verify the decrypted message is not equal to the message, as a failed MAC check should not 
            // leak the plaintext
            Assert.That(decryptedMessage, Is.Not.EqualTo(message));

            // Verify error when the key is invalid
            key[0]++;
            Assert.That(
               () => sb.Decrypt(decryptedMessage, ciphertext, ciphertext.Length, key, context, messageId),
               Throws.TypeOf<CryptographicException>().With.Message.EqualTo("MAC check failed"));
            Assert.That(
               sb.TryDecrypt(decryptedMessage, ciphertext, ciphertext.Length, key, context, messageId),
               Is.False);

            // Verify error when the ciphertext is invalid
            key[0]--;
            ciphertext[12]++;
            Assert.That(
               () => sb.Decrypt(decryptedMessage, ciphertext, ciphertext.Length, key, context, messageId),
               Throws.TypeOf<CryptographicException>().With.Message.EqualTo("MAC check failed"));
            Assert.That(
               sb.TryDecrypt(decryptedMessage, ciphertext, ciphertext.Length, key, context, messageId),
               Is.False);
        }
    }
}
