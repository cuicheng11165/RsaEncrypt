
namespace Gao.Util
{
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;

    public class RsaHelper
    {
        private readonly X509Certificate2 certificate2;

        public RsaHelper(X509Certificate2 certificate2)
        {
            this.certificate2 = certificate2;
        }

        protected RsaHelper()
        {
        }

        /// <summary>
        ///     Using the certificate public key to encrypt a plain text
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        public virtual String Encrypt(String plainText)
        {
#if NET45

            var data = Encoding.UTF8.GetBytes(plainText);
            var rsa = (RSACryptoServiceProvider)this.certificate2.PublicKey.Key;
            var encryptedData = rsa.Encrypt(data, true);
            return Convert.ToBase64String(encryptedData);

#else

            var data = Encoding.UTF8.GetBytes(plainText);
            var rsa = (RSA)this.certificate2.PublicKey.Key;
            var encryptedData = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA1);
            return Convert.ToBase64String(encryptedData);

#endif
        }

        /// <summary>
        ///     Decrypt the cipher text using the certificate private key
        /// </summary>
        /// <param name="encryptedText"></param>
        /// <returns></returns>
        public virtual String Decrypt(String encryptedText)
        {
#if NET45

            if (!this.certificate2.HasPrivateKey)
                throw new InvalidOperationException(
                    "Certificate with public key can't be used for decrypt purpose ");
            var cipherData = Convert.FromBase64String(encryptedText);
            var rsa = (RSACryptoServiceProvider)this.certificate2.PrivateKey;
            var data = rsa.Decrypt(cipherData, true);
            return Encoding.UTF8.GetString(data);

#else

            if (!this.certificate2.HasPrivateKey)
                throw new InvalidOperationException(
                    "Certificate with public key can't be used for decrypt purpose ");
            var cipherData = Convert.FromBase64String(encryptedText);
            var rsa = (RSA)this.certificate2.PrivateKey;
            var data = rsa.Decrypt(cipherData, RSAEncryptionPadding.OaepSHA1);
            return Encoding.UTF8.GetString(data);

#endif
        }

        /// <summary>
        ///     Sign data using the certificate
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        public virtual String SignData(String plainText)
        {
#if NET45
            if (!this.certificate2.HasPrivateKey)
                throw new InvalidOperationException(
                    "Certificate with public key can't be used for signature purpose ");
            var data = Encoding.UTF8.GetBytes(plainText);
            var sha1 = new SHA1CryptoServiceProvider();
            var hashbytes = sha1.ComputeHash(data);
            var signatrueFormatter = new RSAPKCS1SignatureFormatter(this.certificate2.PrivateKey);
            signatrueFormatter.SetHashAlgorithm("SHA1");
            var signature = signatrueFormatter.CreateSignature(hashbytes);
            return Convert.ToBase64String(signature);
#else
            if (!this.certificate2.HasPrivateKey)
                throw new InvalidOperationException(
                    "Certificate with public key can't be used for signature purpose ");
            var data = Encoding.UTF8.GetBytes(plainText);
            var rsa = (RSA)this.certificate2.PrivateKey;
            var signature = rsa.SignData(data, 0, data.Length, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signature);
#endif
        }

        /// <summary>
        ///     verify the data using the signature
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public virtual Boolean VerifyData(String plainText, String signature)
        {
#if NET45

            var data = Encoding.UTF8.GetBytes(plainText);
            var signatureData = Convert.FromBase64String(signature);
            var rsa = (RSACryptoServiceProvider)this.certificate2.PublicKey.Key;
            return rsa.VerifyData(data, "SHA1", signatureData);

#else

            var data = Encoding.UTF8.GetBytes(plainText);
            var signatureData = Convert.FromBase64String(signature);
            var rsa = (RSA)this.certificate2.PublicKey.Key;
            return rsa.VerifyData(data, signatureData, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

#endif
        }
    }
}
