namespace Iron.Internal
{
    internal class EncryptionData
    {
        public byte[] Data { get; set; }
        public IronEncryptionKey Key { get; set; }
    }
}