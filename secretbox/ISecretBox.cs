namespace SecretBox
{
    public interface ISecretBox
    {
        void GenerateKey(byte[] key);

        void Encrypt(
            byte[] ciphertext,
            byte[] message,
            int messageLength,
            byte[] key,
            string context, 
            long messageId);

        void Decrypt(
            byte[] message,
            byte[] ciphertext, 
            int ciphertextLength,
            byte[] key, 
            string context, 
            long messageId = 1);

        bool TryDecrypt(
            byte[] message,
            byte[] ciphertext,
            int ciphertextLength,
            byte[] key, 
            string context,
            long messageId = 1);
    }
}