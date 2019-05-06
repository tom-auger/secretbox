namespace SecretBox
{
    public interface ISecretBox
    {
        void Decrypt(byte[] message, byte[] ciphertext, int ciphertextLength, byte[] key, string context, long messageId = 1);
        void Encrypt(
            byte[] ciphertext,
            byte[] message,
            int messageLength,
            byte[] key,
            string context, 
            long messageId);

        void GenerateKey(byte[] key);
    }
}