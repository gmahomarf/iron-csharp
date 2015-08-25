using System.Security.Cryptography;
using System.Text;

namespace Iron.Algorithms
{
    public class Sha256IronIntegrityAlgorithm : IIronIntegrityAlgoritm
    {
        public int KeyBits { get; private set; }
        public int IvBits { get; private set; }
        public int SaltBits { get; private set; }
        public int Iterations { get; private set; }
        public string Salt { get; set; }
        public byte[] Iv { get; set; }
        
        public byte[] GetHmacHash(IronEncryptionKey key, string data)
        {
            var dataBytes = Encoding.UTF8.GetBytes(data);
            var hmac = new HMACSHA256(key.Key);

            return hmac.ComputeHash(dataBytes);
        }

        public Sha256IronIntegrityAlgorithm()
        {
            KeyBits = 256;
            SaltBits = 256;
            IvBits = -1;
            Iterations = 1;
        }

        public Sha256IronIntegrityAlgorithm(int iterations, int keyBits, int ivBits, int saltBits)
        {
            SaltBits = saltBits;
            IvBits = ivBits;
            KeyBits = keyBits;
            Iterations = iterations;
        }
    }
}