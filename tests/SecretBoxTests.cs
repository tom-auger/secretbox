namespace Tests
{
    using NUnit.Framework;
    using SecretBox;
    using static SecretBox.SecretBox;

    public class SecretBoxTests
    {
        [TestCase(12, Description = "Key too short")]
        [TestCase(44, Description = "Key too long")]
        public void ValidateKeyLength(int keyLength)
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
        public void ValidateMessageLength_TooLong()
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
                    $"'messageLength' must be at least than the length of 'message'"));
        }

        [Test]
        public void ValidateContextLength_TooLong()
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
        public void ValidateCiphertextLength_TooShort()
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
    }
}
