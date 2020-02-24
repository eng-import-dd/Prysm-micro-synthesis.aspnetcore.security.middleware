using System.Security.Cryptography;

namespace Synthesis.AspNetCore.Security.Middleware.DataProtection
{
    internal class Sha256CngProvider : ISha256Provider
    {
        public SHA256 Create()
        {
            return new SHA256Managed();
        }
    }
}