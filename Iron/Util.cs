using System;
using Iron.Internal;

namespace Iron
{
    internal class Util
    {
        public static byte[] RandomBits(int saltBits)
        {
            var bytes = (int)Math.Ceiling((double)saltBits / 8);
            var randomBytes = new byte[bytes];
            var rnd = new Random();
            rnd.NextBytes(randomBytes);

            return randomBytes;
        }

        public static bool FixedTimeComparison(string a, string b)
        {
            var mismatch = a.Length == b.Length ? 0 : 1;
            if (mismatch == 1)
            {
                b = a;
            }

            for (var i = 0; i < a.Length; ++i)
            {
                var ac = a[i];
                var bc = b[i];
                mismatch |= (ac ^ bc);
            }

            return (mismatch == 0);
        }

        public static string ToSafeBase64(byte[] data)
        {
            return Convert.ToBase64String(data).Replace('+', '-').Replace('/', '_').Replace("=", "");
        }

        public static byte[] FromSafeBase64(string data)
        {
            data = data.Replace('-', '+').Replace('_', '/');
            var missingLength = 4 - data.Length % 4;

            if (missingLength != 4)
            {
                for (var i = 0; i < missingLength; i++)
                {
                    data += "=";
                }
            }

            return Convert.FromBase64String(data);
        }

        public static NormalizedPassword NormalizePassword(PasswordObject password)
        {
            var normalizedPassword = new NormalizedPassword
            {
                Id = password.Id,
                Encryption = String.IsNullOrEmpty(password.Secret) ? password.Encryption : password.Secret,
                Integrity = String.IsNullOrEmpty(password.Secret) ? password.Integrity : password.Secret
            };

            return normalizedPassword;
        }
    }
}
