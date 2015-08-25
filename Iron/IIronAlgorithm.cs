namespace Iron
{
    public interface IIronAlgorithm
    {
        /// <summary>
        /// Size of the key in bits.
        /// </summary>
        int KeyBits { get; }

        /// <summary>
        /// Size of the generated IV in bits. IV is only generated if IV is null.
        /// </summary>
        int IvBits { get; }

        /// <summary>
        /// Size of the generated salt in bits. Salt is only generated if Salt is null.
        /// </summary>
        int SaltBits { get; }

        /// <summary>
        /// Number of iterations used to derive a key from the password.
        /// </summary>
        int Iterations { get; }

        /// <summary>
        /// The salt to use instead of generating one.
        /// </summary>
        string Salt { get; set; }

        /// <summary>
        /// The IV to use instead of generating one.
        /// </summary>
        byte[] Iv { get; set; }
    }
}