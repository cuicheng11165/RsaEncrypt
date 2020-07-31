
namespace Gao.Util
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    public class AesEncryptionHelper : EncryptionHelperBase
    {
        /// <summary>
        /// For security reasons, the default IV is different from other ave point system default IV.
        /// Other system default one: private static readonly Byte[] IV = { 201, 219, 55, 183, 156,
        /// 64, 85, 204, 201, 219, 55, 183, 156, 64, 85, 204 };
        /// </summary>
        private static readonly Byte[] vCloudIV =
        {
            121, 119, 125, 103, 216, 64, 111, 104,
            101, 209, 155, 123, 126, 104, 135, 204
        };

        /// <summary>
        /// For security reasons, the default key is different from other ave point system default
        /// key. Other system default one: private static readonly Byte[] IV = { 201, 219, 55, 183,
        /// 156, 64, 85, 204, 201, 219, 55, 183, 156, 64, 85, 204 };
        /// </summary>
        protected virtual Byte[] AesKey { get; set; } =
        {
            101, 209, 155, 143, 176, 164, 185, 214,
            211, 119, 125, 132, 112, 214, 213, 104
        };

        private Boolean isDefaultKey;

        protected virtual Byte[] IV => vCloudIV;

        public override String Key
        {
            get { return Convert.ToBase64String(this.AesKey); }
            set
            {
                this.AesKey = Convert.FromBase64String(value);
                this.isDefaultKey = false;
            }
        }

        public override Boolean IsDefaultKey
        {
            get { return this.isDefaultKey; }
        }

        public override Byte[] Encrypt(Byte[] plainData)
        {
            var iv = this.IV;
            return this.Encrypt(plainData, iv, this.AesKey);
        }

        protected Byte[] Encrypt(Byte[] plainData, Byte[] iv, Byte[] aesKey)
        {
            using (var aesProvider = new AesCryptoServiceProvider())
            {
                using (var stream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(
                        stream,
                        aesProvider.CreateEncryptor(aesKey, iv),
                        CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainData, 0, plainData.Length);
                    }
                    var encryptMessageBytes = stream.ToArray();
                    var bts = new Byte[iv.Length + encryptMessageBytes.Length];
                    Array.Copy(iv, 0, bts, 0, iv.Length);
                    Array.Copy(encryptMessageBytes, 0, bts, iv.Length, encryptMessageBytes.Length);
                    return bts;
                }
            }
        }

        public override Byte[] Decrypt(Byte[] encryptionData)
        {
            return this.Decrypt(encryptionData, this.AesKey);
        }

        protected Byte[] Decrypt(Byte[] encryptionData, Byte[] aesKey)
        {
            using (var aesProvider = new AesCryptoServiceProvider())
            {
                using (var stream = new MemoryStream())
                {
                    var iv = new Byte[16];
                    Array.Copy(encryptionData, 0, iv, 0, iv.Length);
                    using (var cryptoStream = new CryptoStream(
                        stream,
                        aesProvider.CreateDecryptor(aesKey, iv),
                        CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(encryptionData, iv.Length, encryptionData.Length - iv.Length);
                    }
                    return stream.ToArray();
                }
            }
        }

        public override String EncryptString(String plainString)
        {
            var buffer = Encoding.UTF8.GetBytes(plainString);
            var encryptMessageBytes = this.Encrypt(buffer);
            return Convert.ToBase64String(encryptMessageBytes);
        }

        public override String DecryptString(String encryptedString)
        {
            var buffer = Convert.FromBase64String(encryptedString);
            var decryptMessageBytes = this.Decrypt(buffer);
            return Encoding.UTF8.GetString(decryptMessageBytes);
        }
    }
}
