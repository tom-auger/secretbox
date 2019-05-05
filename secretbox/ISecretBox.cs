namespace SecretBox
{
    public interface ISecretBox
    {
        void Encrypt(byte[] ciphertext, byte[] message, int messageLength, long messageId, string context, byte[] key);
        void GenerateKey(byte[] key);
    }
}