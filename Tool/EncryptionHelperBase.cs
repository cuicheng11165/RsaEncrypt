 
namespace Gao.Util
{
    using System;

    public abstract class EncryptionHelperBase : IEncryptionHelper
    {
        public abstract String Key { get; set; }

        public abstract Boolean IsDefaultKey { get; }

        public abstract Byte[] Encrypt(Byte[] plainData);

        public abstract Byte[] Decrypt(Byte[] encryptionData);

        public abstract String EncryptString(String plainString);

        public abstract String DecryptString(String encryptedString);
    }
}
