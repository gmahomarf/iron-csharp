namespace Iron
{
    public class IronEncrypterInitializationOptions
    {
        public int? LocaltimeOffsetMsec { get; set; }
        public int Ttl { get; set; }
        public int TimestampSkewSec { get; set; }
        public IIronEncryptionAlgorithm Encryption { get; set; }
        public IIronIntegrityAlgoritm Integrity { get; set; }
    }
}