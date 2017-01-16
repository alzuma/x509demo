using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace Common
{
    public class Secure
    {
        public bool Verify(string text, string signature, string signThumbprint)
        {
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            try
            {
                var thumbprint = Regex.Replace(signThumbprint, @"[^\da-zA-z]", string.Empty).ToUpper();

                var certificate =
                    store.Certificates.Cast<X509Certificate2>().FirstOrDefault(cert => cert.Thumbprint == thumbprint);

                if (certificate == null)
                {
                    throw new InvalidOperationException($"Cert with thumbprint:{thumbprint} not found");
                }

                var csp = (RSACryptoServiceProvider) certificate.PublicKey.Key;

                var sha256 = new SHA256Managed();

                var data = Encoding.UTF8.GetBytes(text);
                var hash = sha256.ComputeHash(data);

                return csp.VerifyHash(hash, CryptoConfig.MapNameToOID("SHA256"), Convert.FromBase64String(signature));                
            }
            finally
            {
                store.Close();
            }
        }

        public string Sign(string text, string signThumbprint)
        {
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            try
            {
                var thumbprint = Regex.Replace(signThumbprint, @"[^\da-zA-z]", string.Empty).ToUpper();

                var certificate =
                    store.Certificates.Cast<X509Certificate2>().FirstOrDefault(cert => cert.Thumbprint == thumbprint);

                if (certificate == null)
                {
                    throw new InvalidOperationException($"Cert with X509 humbprint:{thumbprint} not found");
                }
                
                var plainData = Encoding.UTF8.GetBytes(text);

                var rsaEncryptor = (RSACryptoServiceProvider)certificate.PrivateKey;

                byte[] signature = null;

                try
                {
                    signature = rsaEncryptor.SignData(plainData, "SHA256");
                }
                catch (Exception)
                {
                    // ignored
                }

                if (signature != null) return Convert.ToBase64String(signature);

                if (!rsaEncryptor.CspKeyContainerInfo.Exportable)
                {
                    throw new InvalidOperationException($"Cert with thumbprint:{thumbprint} needs to either support SHA256 signing, or have an exportable private key!");
                }

                RSAParameters pk;
                try
                {
                    pk = rsaEncryptor.ExportParameters(true);
                }
                catch (Exception)
                {
                    throw new InvalidOperationException($"Cert with thumbprint:{thumbprint} needs to either support SHA256 signing, or have an exportable private key!");
                }

                rsaEncryptor = new RSACryptoServiceProvider();
                try
                {
                    rsaEncryptor.ImportParameters(pk);
                    signature = rsaEncryptor.SignData(plainData, CryptoConfig.MapNameToOID("SHA256"));
                }
                finally
                {
                    rsaEncryptor.Dispose();
                }

                return Convert.ToBase64String(signature);
            }
            finally
            {
                store.Close();
            }
        }
    }
}