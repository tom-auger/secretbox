namespace SecretBox.Internal
{
    public static class Primitive
    {
        public static void Gimli(uint[] state)
        {
            uint x, y, z;

            for (var round = 24; round > 0; --round)
            {
                for (var col = 0; col < 4; ++col)
                {
                    x = Rotate(state[col], 24);
                    y = Rotate(state[4 + col], 9);
                    z = state[8 + col];

                    state[8 + col] = x ^ (z << 1) ^ ((y & z) << 2);
                    state[4 + col] = y ^ x ^ ((x | z) << 1);
                    state[col] = z ^ y ^ ((x & y) << 3);
                }

                if ((round & 3) == 0)
                {
                    // Small swap
                    (state[0], state[1], state[2], state[3]) =
                    (state[1], state[0], state[3], state[2]);
                }
                if ((round & 3) == 2)
                {
                    // Big swap
                    (state[0], state[1], state[2], state[3]) =
                    (state[2], state[3], state[0], state[1]);
                }
                if ((round & 3) == 0)
                {
                    // Add constant
                    state[0] ^= (uint)(0x9e377900 | round);
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
