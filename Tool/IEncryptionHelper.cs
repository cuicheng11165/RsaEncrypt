
namespace Gao.Util
{
    using System;

    public interface IEncryptionHelper
    {
        String Key { get; set; }

        Boolean IsDefaultKey { get; }

        Byte[] Encrypt(Byte[] plainData);

        Byte[] Decrypt(Byte[] encryptionData);

        String EncryptString(String plainString);

        String DecryptString(String encryptedString);
    }
}
