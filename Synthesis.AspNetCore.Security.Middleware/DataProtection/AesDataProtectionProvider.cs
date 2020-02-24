using Microsoft.AspNetCore.DataProtection;

namespace Synthesis.AspNetCore.Security.Middleware.DataProtection
{
    public class AesDataProtectionProvider : IDataProtectionProvider
    {
        private const string AppName = "MJkEBABKOViNPOFfCOFR5cn7Ong5xhaSSdmu1faHeJIR8divJcO1VqmOtsuUK4W";

        private readonly IAesProvider _aesProvider;
        private readonly ISha256Provider _sha256Provider;
        private readonly string _appKey;

        internal static IAesProvider AesProvider { get; set; } = new AesCspProvider();
        internal static ISha256Provider Sha256Provider { get; set; } = new Sha256CngProvider();

        internal AesDataProtectionProvider(IAesProvider aesProvider, ISha256Provider sha256Provider, string appKey)
        {
            _aesProvider = aesProvider;
            _sha256Provider = sha256Provider;
            _appKey = appKey;
        }

        public static IDataProtectionProvider Create()
        {
            return Create(AppName);
        }

        public static IDataProtectionProvider Create(string appKey)
        {
            return new AesDataProtectionProvider(AesProvider, Sha256Provider, appKey);
        }

        public IDataProtector CreateProtector(string purpose)
        {
            return new AesDataProtector(_aesProvider, _sha256Provider, _appKey, "Synthesis.Cloud.DataProtection.IDataProtector", new[] { purpose });
        }
    }
}