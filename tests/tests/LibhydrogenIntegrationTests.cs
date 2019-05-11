namespace Tests
{
    using NUnit.Framework;
    using SecretBox;
    using System.Text;
    using static LibhydrogenInterop;

    public class LibhydrogenIntegrationTests
    {
        [Test]
        public void VerifySecretBoxEncryptedMessageCanBeDecrypted()
        {
            var sb = new SecretBox();
            
            // Generate a key
            var key = new byte[SecretBox.KeyBytes];
            sb.GenerateKey(key);

            // Generate a message to encrypt
            var message = Encoding.UTF8.GetBytes("You are old Father William, the young man said");
            const int messageId = 1;
            const string context = "test";

            // Buffer to hold the ciphertext
            var ciphertext = new byte[sb.CalculateCiphertextLength(message.Length)];

            // Encrypt using SecretBox
            sb.Encrypt(ciphertext, message, message.Length, key, context, messageId);
            
            // Verify that some ciphertext was generated
            Assert.That(ciphertext, Is.Not.All.Zero);

            // Decrypt using libhydrogen
            var decryptedMessage = new byte[message.Length];
            var result = hydro_secretbox_decrypt(
                decryptedMessage, ciphertext, ciphertext.Length, messageId, context, key);

            // Verify the decrypt was successful
            Assert.That(result, Is.EqualTo(0));
            Assert.That(decryptedMessage, Is.EqualTo(message));
        }

        [Test]
        public void VerifyLibhydrogenEncryptedMessageCanBeDecrypted()
        {
            var sb = new SecretBox();

            // Generate a key
            var key = new byte[SecretBox.KeyBytes];
            sb.GenerateKey(key);

            // Generate a message to encrypt
            var message = Encoding.UTF8.GetBytes("You are old Father William, the young man said");
            const int messageId = 1;
            const string context = "test";

            // Buffer to hold the ciphertext
            var ciphertext = new byte[sb.CalculateCiphertextLength(message.Length)];

            // Encrypt using libhydrogen
            var result = hydro_secretbox_encrypt(
                ciphertext, message, message.Length, messageId, context, key);

            // Verify that some ciphertext was generated
            Assert.That(ciphertext, Is.Not.All.Zero);
            Assert.That(result, Is.EqualTo(0));

            // Decrypt using SecretBox
            var decryptedMessage = new byte[message.Length];
            sb.Decrypt(decryptedMessage, ciphertext, ciphertext.Length, key, context, messageId);

            // Verify the decrypt was successful
            Assert.That(decryptedMessage, Is.EqualTo(message));
        }
    }
}
