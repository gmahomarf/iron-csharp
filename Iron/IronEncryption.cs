using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Iron.Algorithms;
using Iron.Internal;
using Newtonsoft.Json;

namespace Iron
{
    public class IronEncryption
    {
        #region Private members

        private readonly IronEncrypterInitializationOptions _options;

        private IronEncryptionKey GenerateKey(string password, IIronAlgorithm algorithm)
        {
            if (String.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException("password");
            }

            if (algorithm == null)
            {
                throw new ArgumentNullException("algorithm");
            }

            Rfc2898DeriveBytes derivedBytes;
            if (algorithm.Salt == null && algorithm.SaltBits > 0)
            {
                algorithm.Salt = BitConverter.ToString(Util.RandomBits(algorithm.SaltBits)).Replace("-", "").ToLower();
            }
            if (algorithm.Salt != null)
            {
                derivedBytes = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes(algorithm.Salt), algorithm.Iterations);
            }
            else
            {
                throw new ArgumentException("No Salt was given and SaltBits is too small (must be greater than 0).", "algorithm");
            }

            var ivBits = algorithm.IvBits;
            var iv = algorithm.Iv ?? (ivBits > 0 ? Util.RandomBits(ivBits) : null);

            return new IronEncryptionKey
            {
                Iv = iv,
                Key = derivedBytes.GetBytes((int) Math.Ceiling((double) algorithm.KeyBits/8)),
                Salt = Encoding.UTF8.GetString(derivedBytes.Salt)
            };
        }

        private EncryptionData Encrypt(string password, IIronEncryptionAlgorithm algorithm, string data)
        {
            if (String.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException("password");
            }

            if (algorithm == null)
            {
                throw new ArgumentNullException("algorithm");
            }

            IronEncryptionKey key = GenerateKey(password, algorithm);

            return new EncryptionData
            {
                Data = algorithm.Encrypt(key, data),
                Key = key
            };
        }

        private string Decrypt(string password, IIronEncryptionAlgorithm algorithm, byte[] data)
        {
            if (String.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException("password");
            }

            if (algorithm == null)
            {
                throw new ArgumentNullException("algorithm");
            }

            IronEncryptionKey key = GenerateKey(password, algorithm);

            return algorithm.Decrypt(key, data);
        }

        private HmacResult HmacWithPassword(string password, IIronIntegrityAlgoritm algorithm, string data)
        {
            if (String.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException("password");
            }

            if (algorithm == null)
            {
                throw new ArgumentNullException("algorithm");
            }

            var key = GenerateKey(password, algorithm);

            var hash = algorithm.GetHmacHash(key, data);

            var base64Bytes = Util.ToSafeBase64(hash);
            return new HmacResult
            {
                Digest = base64Bytes,
                Salt = key.Salt
            };
        }

        #endregion

        #region Public members

        public static readonly string MacFormatVersion = "2";
        public static readonly string MacPrefix = "Fe26." + MacFormatVersion;

        /// <summary>
        /// Iron Encryption default options.
        /// </summary>
        public static readonly IronEncrypterInitializationOptions Defaults = new IronEncrypterInitializationOptions
        {
            Encryption = new Aes256CbcIronEncryptionAlgorithm(),
            Integrity = new Sha256IronIntegrityAlgorithm(),
            LocaltimeOffsetMsec = 0,
            TimestampSkewSec = 60,
            Ttl = 0
        };

        public IronEncryption()
        {
            _options = Defaults;
        }

        public IronEncryption(IronEncrypterInitializationOptions options)
        {
            _options = options;
        }

        /// <summary>
        /// Serializes and seals <paramref name="data"/>.
        /// </summary>
        /// <param name="data">The object to seal.</param>
        /// <param name="password">The password to use in key generation.</param>
        /// <param name="options"></param>
        /// <returns>A string containing the sealed data.</returns>
        public string Seal(object data, string password, IronEncrypterInitializationOptions options = null)
        {
            var passwordObject = new PasswordObject
            {
                Secret = password
            };

            return Seal(data, passwordObject, options);
        }

        /// <summary>
        /// Serializes and seals <paramref name="data"/>.
        /// </summary>
        /// <param name="data">The object to seal.</param>
        /// <param name="password">The password to use in key generation.</param>
        /// <param name="options"></param>
        /// <returns>A string containing the sealed data.</returns>
        public string Seal(object data, PasswordObject password, IronEncrypterInitializationOptions options = null)
        {
            if (options == null)
            {
                options = _options;
            }
            var now = DateTime.Now.Subtract(new DateTime(1970, 1, 1)).TotalMilliseconds +
                      (options.LocaltimeOffsetMsec ?? 0);
            var dataString = JsonConvert.SerializeObject(data);

            var normalizedPassword = Util.NormalizePassword(password);

            var passwordId = normalizedPassword.Id ?? "";

            var encryptionData = Encrypt(normalizedPassword.Encryption, options.Encryption, dataString);

            var base64EncryptedData = Util.ToSafeBase64(encryptionData.Data);
            var base64Iv = Util.ToSafeBase64(encryptionData.Key.Iv);
            var expiration = (options.Ttl > 0 ? (now + options.Ttl).ToString(CultureInfo.InvariantCulture) : "");

            var macBaseString = MacPrefix + "*" + passwordId + "*" +
                                encryptionData.Key.Salt +
                                "*" + base64Iv + "*" + base64EncryptedData + "*" + expiration;

            var hmac = HmacWithPassword(normalizedPassword.Integrity, options.Integrity, macBaseString);

            var sealedData = macBaseString + "*" + hmac.Salt + "*" +
                             hmac.Digest;

            return sealedData;
        }

        /// <summary>
        /// Unseals and deserializes an object of type <typeparamref name="T"/> from the provided <paramref name="sealedData"/>.
        /// </summary>
        /// <typeparam name="T">The type of the object sealed within <paramref name="sealedData"/>.</typeparam>
        /// <param name="sealedData">The sealed object.</param>
        /// <param name="password">The password used in key generation.</param>
        /// <param name="options"></param>
        /// <returns>An unsealed and deserialized object of type <typeparamref name="T"/></returns>
        public T Unseal<T>(string sealedData, string password, IronEncrypterInitializationOptions options = null)
        {
            var passwordObject = new PasswordObject
            {
                Secret = password
            };

            return Unseal<T>(sealedData, passwordObject, options);
        }

        /// <summary>
        /// Unseals and deserializes an object of type <typeparamref name="T"/> from the provided <paramref name="sealedData"/>.
        /// </summary>
        /// <typeparam name="T">The type of the object sealed within <paramref name="sealedData"/>.</typeparam>
        /// <param name="sealedData">The sealed object.</param>
        /// <param name="password">The password used in key generation.</param>
        /// <param name="options"></param>
        /// <returns>An unsealed and deserialized object of type <typeparamref name="T"/></returns>
        public T Unseal<T>(string sealedData, PasswordObject password, IronEncrypterInitializationOptions options = null)
        {
            if (options == null)
            {
                options = _options;
            }
            var now = DateTime.Now.Subtract(new DateTime(1970, 1, 1)).TotalMilliseconds +
                      (options.LocaltimeOffsetMsec ?? 0);


            var parts = sealedData.Split('*');

            var macPrefix = parts[0];
            var passwordId = parts[1];
            var encryptionSalt = parts[2];
            var encryptionIv = parts[3];
            var encryptedB64 = parts[4];
            var expiration = parts[5];
            var hmacSalt = parts[6];
            var hmac = parts[7];
            var macBaseString = macPrefix + '*' + passwordId + '*' + encryptionSalt + '*' + encryptionIv + '*' +
                                encryptedB64 + '*' + expiration;

            if (macPrefix != MacPrefix)
            {
                throw new Exception("Wrong mac prefix");
            }

            if (!String.IsNullOrEmpty(expiration))
            {
                var exp = int.Parse(expiration);
                if (exp <= (now - (options.TimestampSkewSec * 1000)))
                {
                    throw new Exception("Expired Seal");
                }
            }

            var normalizedPassword = Util.NormalizePassword(password);

            var macOptions = options.Integrity;

            macOptions.Salt = hmacSalt;

            var mac = HmacWithPassword(normalizedPassword.Integrity, macOptions, macBaseString);

            if (!Util.FixedTimeComparison(mac.Digest, hmac))
            {
                throw new Exception("Bad hmac value");
            }

            var encrypted = Util.FromSafeBase64(encryptedB64);
            var decryptionAlgorithm = options.Encryption;
            decryptionAlgorithm.Salt = encryptionSalt;
            decryptionAlgorithm.Iv = Util.FromSafeBase64(encryptionIv);

            var decrypted = Decrypt(normalizedPassword.Encryption, decryptionAlgorithm, encrypted);

            var obj = JsonConvert.DeserializeObject<T>(decrypted);

            return obj;
        }

        #endregion
    }
}