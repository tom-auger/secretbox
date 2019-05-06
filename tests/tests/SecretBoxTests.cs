namespace Tests
{
    using NUnit.Framework;
    using SecretBox;
    using static SecretBox.SecretBox;

    public class SecretBoxTests
    {
        [TestCase(12, Description = "Key too short")]
        [TestCase(44, Description = "Key too long")]
        public void Encrypt_ValidateKeyLength(int keyLength)
        {
            var key = new byte[keyLength];
            const int mlen = 12;
            var m = new byte[mlen];
            var c = new byte[mlen + HeaderBytes];
            var ctx = "test";

            var sb = new SecretBox();
            Assert.That(
                () => sb.Encrypt(c, m, mlen, key, ctx), 
                Throws.ArgumentException.With.Message.EqualTo(
                    $"'key' length must be {KeyBytes} bytes"));
        }

        [Test]
        public void Encrypt_ValidateMessageLength_TooLong()
        {
            var key = new byte[KeyBytes];
            const int mlen = 44;
            const int mlenActual = 12;
            var m = new byte[mlenActual];
            var c = new byte[mlenActual + HeaderBytes];
            var ctx = "test";

            var sb = new SecretBox();
            Assert.That(
                () => sb.Encrypt(c, m, mlen, key, ctx),
                Throws.ArgumentException.With.Message.EqualTo(
                    $"'messageLength' must be at most the length of 'message'"));
        }

        [Test]
        public void Encrypt_ValidateContextLength_TooLong()
        {
            var key = new byte[KeyBytes];
            const int mlen = 12;
            var m = new byte[mlen];
            var c = new byte[mlen + HeaderBytes];
            var ctx = "you are old father william";

            var sb = new SecretBox();
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
            var key = new byte[keyLength];
            const int clen = 100;
            var c = new byte[clen];
            var m = new byte[clen - HeaderBytes];
            var ctx = "test";

            var sb = new SecretBox();
            Assert.That(
                () => sb.Decrypt(m, c, clen, key, ctx),
                Throws.ArgumentException.With.Message.EqualTo(
                    $"'key' length must be {KeyBytes} bytes"));
        }

        [Test]
        public void Decrypt_ValidateCiphertextLength_TooLong()
        {
            var key = new byte[KeyBytes];
            const int clen = 200;
            const int clenActual = 100;
            var c = new byte[clenActual];
            var m = new byte[clenActual - HeaderBytes];
            var ctx = "test";

            var sb = new SecretBox();
            Assert.That(
                () => sb.Decrypt(m, c, clen, key, ctx),
                Throws.ArgumentException.With.Message.EqualTo(
                    $"'ciphertextLength' must be at most the length of 'ciphertext'"));
        }

        [Test]
        public void Decrypt_ValidateContextLength_TooLong()
        {
            var key = new byte[KeyBytes];
            const int clen = 100;
            var c = new byte[clen];
            var m = new byte[clen - HeaderBytes];
            var ctx = "you are old father william";

            var sb = new SecretBox();
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
    }
}
