using System.Security.Cryptography;

namespace Synthesis.AspNetCore.Security.Middleware.DataProtection
{
    internal interface ISha256Provider
    {
        SHA256 Create();
    }
}