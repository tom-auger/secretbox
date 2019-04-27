namespace SecretBox.Internal
{
    public static class Primitive
    {
        /// <summary>
        /// This is a C# translation of the c-ref implementation of 
        /// the Gimli permutation taken from https://gimli.cr.yp.to/impl.html.
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
