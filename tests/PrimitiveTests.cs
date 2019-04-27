namespace Tests
{
    using NUnit.Framework;
    using System.Linq;

    public class PrimitiveTests
    {
        [Test]
        public void Test_TestVector()
        {
            // Generate the test vector
            var tv = Enumerable.Range(0, 12)
                .Select(i => (uint)(i * i * i + i * 0x9e3779b9))
                .ToArray();

            // Perform the Gimli permutation
            SecretBox.Internal.Primitive.Gimli(tv);

            // Verify it equals the expected output
            var tvExp = new uint[] 
            {
                0xba11c85a, 0x91bad119, 0x380ce880, 0xd24c2c68,
                0x3eceffea, 0x277a921c, 0x4f73a0bd, 0xda5a9cd8,
                0x84b673f0, 0x34e52ff7, 0x9e2bef49, 0xf41bb8d6
            };

            Assert.That(tv, Is.EqualTo(tvExp));
        }
    }
}