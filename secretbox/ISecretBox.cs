namespace SecretBox
{
    /// <summary>
    /// A symmetric key cipher using the Gimli permutation.
    /// </summary>
    public interface ISecretBox
    {
        /// <summary>
        /// Generates an encryption key.
        /// </summary>
        /// <param name="key">The buffer in which to place the generated key.</param>
        void GenerateKey(byte[] key);

        /// <summary>
        /// Encrypt a message using the given key, with context and optional message Id.
        /// </summary>
        /// <param name="ciphertext">A buffer in which to place the generated ciphertext.</param>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="messageLength">The length of the message to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="context">A string of maximum 8 characters describing the context.</param>
        /// <param name="messageId">Optional message Id. Defaults to 1.</param>
        void Encrypt(
            byte[] ciphertext,
            byte[] message,
            int messageLength,
            byte[] key,
            string context, 
            long messageId);

        /// <summary>
        /// Decrypt a ciphertext using the given key, with context and optional message Id.
        /// </summary>
        /// <param name="message">A buffer in which to place the decrypted message.</param>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="ciphertextLength">The length of the ciphertext to decrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="context">A string of maximum 8 characters describing the context.</param>
        /// <param name="messageId">Optional message Id. Defaults to 1.</param>
        void Decrypt(
            byte[] message,
            byte[] ciphertext, 
            int ciphertextLength,
            byte[] key, 
            string context, 
            long messageId = 1);

        /// <summary>
        /// Decrypt a ciphertext using the given key, with context and optional message Id.
        /// </summary>
        /// <param name="message">A buffer in which to place the decrypted message.</param>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="ciphertextLength">The length of the ciphertext to decrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="context">A string of maximum 8 characters describing the context.</param>
        /// <param name="messageId">Optional message Id. Defaults to 1.</param>
        /// <returns>Whether the decryption succeeded or not.</returns>
        bool TryDecrypt(
            byte[] message,
            byte[] ciphertext,
            int ciphertextLength,
            byte[] key, 
            string context,
            long messageId = 1);
        
        /// <summary>
        /// Calculates the length of the ciphertext when encrypting a message of the given length.
        /// </summary>
        /// <param name="messageLength">The length of the message to encrypt.</param>
        /// <returns>The length of the ciphertext.</returns>
        int CalculateCiphertextLength(int messageLength);

        /// <summary>
        /// Calculates the length of the message when decrypting a ciphertext of the given length.
        /// </summary>
        /// <param name="ciphertextLength">The length of the ciphertext to decrypt.</param>
        /// <returns>The length of the decrypted message.</returns>
        int CalculateMessageLength(int ciphertextLength);
    }
}