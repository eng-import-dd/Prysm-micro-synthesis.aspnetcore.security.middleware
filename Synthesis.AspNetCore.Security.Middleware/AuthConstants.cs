using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synthesis.AspNetCore.Security.Middleware
{
    internal static class AuthConstants
    {
        internal const string AuthorizationHeaderName = "Authorization";
        internal const string BearerAuthPrefix = "Bearer ";
    }
}
