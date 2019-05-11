﻿namespace SecretBox.Internal
{
    using static Utilities;

    /// <summary>
    /// A C# translation of the c-ref implementation of the Gimli permutation.
    /// </summary>
    public static class Primitive
    {
        internal const int GimliBlockBytes = 48;
        internal const int GimliRate = 16;
        internal const int GimliCapacity = 32;

        internal const byte GimliDomainAEAD = 0x0;
        internal const byte GimliDomainXOF = 0xf;

        internal const byte GimliTagKey = 0xff;
        internal const byte GimliTagKey0 = 0xfe;
        internal const byte GimliTagFinal0 = 0xf8;
        internal const byte GimliTagFinal = 0x08;

        /// <summary>
        /// <para>
        /// This is a C# translation of the c-ref implementation of 
        /// the Gimli permutation taken from https://gimli.cr.yp.to/impl.html. 
        /// </para>
        /// This is not intended for general usage! Only use for building your 
        /// own constructions.
        /// </summary>
        /// <param name="state">An array of 48 bytes on which to perform the Gimli permutation.</param>
        /// <param name="tag">A single byte tag to add to the end of the state.</param>
        public static void Gimli(byte[] state, byte tag)
        {
            // Add the tag onto the end of the state
            state[GimliBlockBytes - 1] ^= tag;
            
            // Convert the 8 bit ints to 32 bit ints
            var converter = new ByteUintConverter { Bytes = state };
            var stateUint = converter.Uints;

            // Perform the Gimli permutation
            Gimli(stateUint);
        }

        /// <summary>
        /// <para>
        /// This is a C# translation of the c-ref implementation of 
        /// the Gimli permutation taken from https://gimli.cr.yp.to/impl.html. 
        /// </para>
        /// This is not intended for general usage! Only use for building your 
        /// own constructions.
        /// </summary>
        /// <param name="state">A 12 element vector on which to perform the Gimli permutation.</param>
        public static void Gimli(uint[] state)
        {
            uint x, y, z;

            for (var round = 24; round > 0; round--)
            {
                for (var col = 0; col < 4; col++)
                {
                    x = Rotate(state[col    ], 24);
                    y = Rotate(state[col + 4], 9);
                    z =        state[col + 8];

                    state[col + 8] = x ^ (z << 1) ^ ((y & z) << 2);
                    state[col + 4] = y ^ x        ^ ((x | z) << 1);
                    state[col    ] = z ^ y        ^ ((x & y) << 3);
                }

                if ((round & 3) == 0)
                {
                    // Small swap
                    (state[0], state[1], state[2], state[3]) =
                    (state[1], state[0], state[3], state[2]);

                    // Add constant
                    state[0] ^= (uint)(0x9e377900 | round);
                }
                else if ((round & 3) == 2)
                {
                    // Big swap
                    (state[0], state[1], state[2], state[3]) =
                    (state[2], state[3], state[0], state[1]);
                }
            }            
        }

        private static uint Rotate(uint x, int bits)
        {
            if (bits == 0) return x;
            return (x << bits) | (x >> (32 - bits));
        }
    }
}
