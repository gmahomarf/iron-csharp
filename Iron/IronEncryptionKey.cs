namespace Iron
{
    public class IronEncryptionKey
    {
        public byte[] Key { get; set; }
        public string Salt { get; set; }
        public byte[] Iv { get; set; }
    }
}