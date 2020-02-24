using System.Threading;
using System.Threading.Tasks;

namespace Synthesis.AspNetCore.Security.Middleware
{
    public interface IAuthTokenConverter
    {
        Task<string> ConvertAsync(string token, CancellationToken cancellationToken = default(CancellationToken));
    }
}
