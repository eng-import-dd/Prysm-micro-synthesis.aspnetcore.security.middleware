using System;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;

namespace Synthesis.AspNetCore.Security.Middleware.DataProtection
{
    internal class AesDataProtector : IDataProtector
    {
        private readonly IAesProvider _aesProvider;
        private readonly ISha256Provider _sha256Provider;
        private readonly byte[] _keyMaterial;
        private readonly string _appKey;
        public AesDataProtector(IAesProvider aesProvider, ISha256Provider sha256Provider, string key, string primaryPurpose, string[] specificPurposes)
        {
            _aesProvider = aesProvider;
            _sha256Provider = sha256Provider;
            _appKey = key;
            
            using (var sha = _sha256Provider.Create())
            {
                using (var writer = new BinaryWriter(new CryptoStream(new MemoryStream(), sha, CryptoStreamMode.Write), new UTF8Encoding(false, true)))
                {
                    writer.Write(key);
                    writer.Write(primaryPurpose);
                    if (specificPurposes != null)
                    {
                        foreach (var purpose in specificPurposes)
                        {
                            writer.Write(purpose);
                        }
                    }
                }

                _keyMaterial = sha.Hash;
            }
        }

        /// <inheritdoc/>
        public byte[] Protect(byte[] userData)
        {
            byte[] dataHash;

            using (var sha = _sha256Provider.Create())
            {
                dataHash = sha.ComputeHash(userData);
            }

            using (var algorithm = _aesProvider.Create())
            {
                algorithm.Key = _keyMaterial;
                algorithm.GenerateIV();

                using (var encryptor = algorithm.CreateEncryptor(algorithm.Key, algorithm.IV))
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        msEncrypt.Write(algorithm.IV, 0, 16);

                        using (var stream = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (var writer = new BinaryWriter(stream))
                            {
                                writer.Write(dataHash);
                                writer.Write(userData.Length);
                                writer.Write(userData);
                            }
                        }

                        return msEncrypt.ToArray();
                    }
                }
            }
        }

        /// <inheritdoc/>
        public byte[] Unprotect(byte[] protectedData)
        {
            using (var algorithm = _aesProvider.Create())
            {
                algorithm.Key = _keyMaterial;

                using (var cipherStream = new MemoryStream(protectedData))
                {
                    var iv = new byte[16];
                    cipherStream.Read(iv, 0, 16);
                    algorithm.IV = iv;

                    if (algorithm.Key == null)
                    {
                        throw new InvalidOperationException("The provided cryptographic key must not be null.");
                    }

                    using (var decryptor = algorithm.CreateDecryptor(algorithm.Key, algorithm.IV))
                    {
                        using (var decryptStream = new CryptoStream(cipherStream, decryptor, CryptoStreamMode.Read))
                        {
                            using (var reader = new BinaryReader(decryptStream))
                            {
                                var signature = reader.ReadBytes(32);
                                var len = reader.ReadInt32();
                                var data = reader.ReadBytes(len);
                                byte[] dataHash;

                                using (var sha = _sha256Provider.Create())
                                {
                                    dataHash = sha.ComputeHash(data);
                                }

                                if (!dataHash.SequenceEqual(signature))
                                {
                                    throw new SecurityException("Signature does not match the computed hash");
                                }

                                return data;
                            }
                        }
                    }
                }
            }
        }

        public IDataProtector CreateProtector(string purpose)
        {
            return new AesDataProtector(_aesProvider, _sha256Provider, _appKey, "Synthesis.Cloud.DataProtection.IDataProtector", new[] { purpose });
        }
    }
}