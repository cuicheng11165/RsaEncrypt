
namespace Gao.Util
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;


    public class RandomKeyEncryptionHelper : AesEncryptionHelper
    {
        private static Int32 keySize = 16;
        private readonly X509Certificate2 certificate;

     

        public RandomKeyEncryptionHelper(X509Certificate2 certificate)
        {
            this.certificate = certificate;
        }

        public override String EncryptString(String plainString)
        {
            var currentIV =  SecurityKeyGenerator.Generate();
            var currentKey = SecurityKeyGenerator.Generate(keySize);

            var plainTextBytes = Encoding.UTF8.GetBytes(plainString);
            var encryptTextBytes = this.Encrypt(plainTextBytes, currentIV, currentKey);
            var encryptKeyText = new SecurityKeyEncryptor(this.certificate).Encrypt(currentKey);
            return encryptKeyText + "." + Convert.ToBase64String(encryptTextBytes);
        }

        public override Byte[] Encrypt(Byte[] plainData)
        {
            var plainText = Encoding.UTF8.GetString(plainData);
            return Encoding.UTF8.GetBytes(this.EncryptString(plainText));
        }

        public override String DecryptString(String encryptedString)
        {
            var bytes = encryptedString.Split('.');
            if (bytes.Length != 2)
            {
                throw new ArgumentException(encryptedString);
            }
            var currentKey = new SecurityKeyEncryptor(this.certificate).DecryptToBytes(bytes[0]);
            var decryptTextBytes = this.Decrypt(Convert.FromBase64String(bytes[1]), currentKey);
            return Encoding.UTF8.GetString(decryptTextBytes);
        }

        public override Byte[] Decrypt(Byte[] encryptionData)
        {
            var encryptedText = Encoding.UTF8.GetString(encryptionData);
            return Encoding.UTF8.GetBytes(this.DecryptString(encryptedText));
        }

        public override String Key
        {
            get { throw new NotSupportedException(); }
        }

        public override Boolean IsDefaultKey
        {
            get { return false; }
        }
    }
}
