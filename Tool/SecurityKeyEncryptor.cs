
namespace Gao.Util
{
    using System;
    using System.Security.Cryptography.X509Certificates;

    public class SecurityKeyEncryptor
    {
        private readonly RsaHelper rsaHelper;

     

        public SecurityKeyEncryptor(X509Certificate2 certificate2)
        {
            this.rsaHelper = new RsaHelper(certificate2);
        }

        public String Encrypt(String plainKey)
        {
            return this.rsaHelper.Encrypt(plainKey);
        }

        public String Encrypt(Byte[] keys)
        {
            var plainKey = Convert.ToBase64String(keys);
            return this.Encrypt(plainKey);
        }

        public String Decrypt(String cipherKey)
        {
            return this.rsaHelper.Decrypt(cipherKey);
        }

        public Byte[] DecryptToBytes(String cipherKey)
        {
            return Convert.FromBase64String(this.Decrypt(cipherKey));
        }

        public String SignData(String plainText)
        {
            return this.rsaHelper.SignData(plainText);
        }

        //public String SignData256(String plainText)
        //{
        //    return this.rsaHelper.SignData256(plainText);
        //}

        public Boolean VerifyData(String plainText, String signature)
        {
            return this.rsaHelper.VerifyData(plainText, signature);
        }
    }
}
