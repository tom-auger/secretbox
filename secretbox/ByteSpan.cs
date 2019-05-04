namespace SecretBox
{
    using System;

    /// <summary>
    /// This facade around a byte array that permits indexing relative to 
    /// an offset.
    /// </summary>
    internal struct ByteSpan
    {
        private ArraySegment<byte> array;

        public ByteSpan(byte[] array, int offset, int count)
        {
            this.array = new ArraySegment<byte>(array, offset, count);
        }

        public byte this[int i]
        {
            get => array.Array[array.Offset + i];
            set => array.Array[array.Offset + i] = value;
        }
    }
}
