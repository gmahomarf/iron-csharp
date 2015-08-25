using System.ComponentModel;

namespace Iron
{
    public interface IIronEncryptionAlgorithm : IIronAlgorithm
    {
        /// <summary>
        /// Encrypts <paramref name="plainTextData"/> using <paramref name="key"/>.
        /// </summary>
        /// <param name="key">The key used to encrypt <paramref name="plainTextData"/>.</param>
        /// <param name="plainTextData">The plain text string to encrypt.</param>
        /// <returns>A byte[] containing the encrypted data.</returns>
        byte[] Encrypt(IronEncryptionKey key, string plainTextData);

        /// <summary>
        /// Decrypts <paramref name="encryptedBytes"/> using <paramref name="key"/>
        /// </summary>
        /// <param name="key">The key used to decrypt <paramref name="encryptedBytes"/>.</param>
        /// <param name="encryptedBytes">A byte[] containing the encrypted data.</param>
        /// <returns>The decrypted data as a string.</returns>
        string Decrypt(IronEncryptionKey key, byte[] encryptedBytes);
    }
}