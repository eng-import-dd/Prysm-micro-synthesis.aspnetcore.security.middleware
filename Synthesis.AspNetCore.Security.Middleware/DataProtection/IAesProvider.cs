using System.Security.Cryptography;

namespace Synthesis.AspNetCore.Security.Middleware.DataProtection
{
    internal interface IAesProvider
    {
        Aes Create();
    }
}