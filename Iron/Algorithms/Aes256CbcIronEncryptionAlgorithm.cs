using System.IO;
using System.Security.Cryptography;

namespace Iron.Algorithms
{
    public class Aes256CbcIronEncryptionAlgorithm : IIronEncryptionAlgorithm
    {
        public int KeyBits { get; private set; }
        public int IvBits { get; private set; }
        public int SaltBits { get; private set; }
        public int Iterations { get; private set; }
        public string Salt { get; set; }
        public byte[] Iv { get; set; }

        public Aes256CbcIronEncryptionAlgorithm()
        {
            IvBits = 128;
            KeyBits = 256;
            SaltBits = 256;
            Iterations = 1;
        }

        public Aes256CbcIronEncryptionAlgorithm(int keyBits, int ivBits, int saltBits, int iterations)
        {
            KeyBits = keyBits;
            IvBits = ivBits;
            SaltBits = saltBits;
            Iterations = iterations;
        }

        public byte[] Encrypt(IronEncryptionKey key, string plainTextData)
        {
            using (var aesManaged = new AesManaged())
            using (var encryptor = aesManaged.CreateEncryptor(key.Key, key.Iv))
            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                using (var streamWriter = new StreamWriter(cryptoStream))
                {
                    streamWriter.Write(plainTextData);
                }

                return memoryStream.ToArray();
            }
        }

        public string Decrypt(IronEncryptionKey key, byte[] encryptedBytes)
        {
            using (var aesManaged = new AesManaged())
            using (var decryptor = aesManaged.CreateDecryptor(key.Key, key.Iv))
            using (var memoryStream = new MemoryStream(encryptedBytes))
            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
            using (var streamReader = new StreamReader(cryptoStream))
            {
                return streamReader.ReadToEnd();
            }
        }
    }
}
