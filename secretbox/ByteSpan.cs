namespace SecretBox
{
    using System;

    internal struct ByteSpan
    {
        private ArraySegment<byte> array;

        public ByteSpan(byte[] a, int offset, int count)
        {
            this.array = new ArraySegment<byte>(a, offset, count);
        }

        public byte this[int i]
        {
            get => array.Array[array.Offset + i];
            set => array.Array[array.Offset + i] = value;
        }
    }
}
