
namespace Gao.Util
{
    using System;
    using System.Security.Cryptography;

    public class SecurityKeyGenerator
    {
        /// <summary>
        ///     This method is to generate a 128 bit key
        /// </summary>
        /// <returns></returns>
        public static Byte[] Generate(Int32 keyLength = 16)
        {
            var keys = new Byte[keyLength];
            var rngCryptoProvider = new RNGCryptoServiceProvider();
            rngCryptoProvider.GetBytes(keys);
            return keys;
        }

        /// <summary>
        ///     Convert the key to a base 64 String
        /// </summary>
        /// <param name="keyLength"></param>
        /// <returns></returns>
        public static String GenerateKeyAsBase64String(Int32 keyLength = 16)
        {
            return Convert.ToBase64String(Generate(keyLength));
        }
    }
}
