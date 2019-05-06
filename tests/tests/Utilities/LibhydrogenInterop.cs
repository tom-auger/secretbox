namespace Tests
{
    using System.Runtime.InteropServices;

    internal static class LibhydrogenInterop
    {
        private const string LibhydrogenDll = "Libhydrogen.dll";

        [DllImport(LibhydrogenDll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hydro_init();

        [DllImport(LibhydrogenDll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hydro_secretbox_encrypt(
            byte[] c,
            byte[] m,
            int mlen,
            long msg_id,
            string ctx,
            byte[] key);

        [DllImport(LibhydrogenDll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hydro_secretbox_decrypt(
            byte[] m,
            byte[] c,
            int clen,
            long msg_id,
            string ctx,
            byte[] key);
    }
}
