namespace SecretBox
{
    public interface ISecretBox
    {
        void Encrypt(byte[] ciphertext, byte[] message, int messageLength, byte[] key, string context, long messageId);
        void GenerateKey(byte[] key);
    }
}