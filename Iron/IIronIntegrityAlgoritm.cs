namespace Iron
{
    public interface IIronIntegrityAlgoritm : IIronAlgorithm
    {
        /// <summary>
        /// Calculates an HMAC Hash of <paramref name="data"/> using <paramref name="key"/> and the current algorithm.
        /// </summary>
        /// <param name="key">The key used to generate the hash.</param>
        /// <param name="data">The data to hash.</param>
        /// <returns>A byte[] object with the hash.</returns>
        byte[] GetHmacHash(IronEncryptionKey key, string data);
    }
}