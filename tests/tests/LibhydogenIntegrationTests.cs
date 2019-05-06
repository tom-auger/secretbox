namespace Tests
{
    using NUnit.Framework;
    using SecretBox;
    using System.Text;
    using static LibhydrogenInterop;

    public class LibhydogenIntegrationTests
    {
        [Test]
        public void VerifyEncryptedMessageCanBeDecrypted()
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
            var ciphertext = new byte[message.Length + SecretBox.HeaderBytes];

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
    }
}
