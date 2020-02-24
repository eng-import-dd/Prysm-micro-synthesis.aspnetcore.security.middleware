using System.Security.Cryptography;

namespace Synthesis.AspNetCore.Security.Middleware.DataProtection
{
    internal class AesCspProvider : IAesProvider
    {
        public Aes Create()
        {
            return new AesCryptoServiceProvider();
        }
    }
}