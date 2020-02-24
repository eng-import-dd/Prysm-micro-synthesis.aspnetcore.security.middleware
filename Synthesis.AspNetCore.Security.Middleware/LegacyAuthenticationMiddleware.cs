using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Synthesis.Logging;
using static Synthesis.AspNetCore.Security.Middleware.AuthConstants;

namespace Synthesis.AspNetCore.Security.Middleware
{
    public class LegacyAuthenticationMiddleware
    {
        private readonly IAuthTokenConverter _authTokenConverter;
        private readonly Lazy<ILogger> _lazyLogger;
        private readonly RequestDelegate _next;
        
        /// <inheritdoc />
        public LegacyAuthenticationMiddleware(
            RequestDelegate next,
            IAuthTokenConverter authTokenConverter,
            ILoggerFactory loggerFactory)
        {
            _authTokenConverter = authTokenConverter;
            _next = next;
            _lazyLogger = new Lazy<ILogger>(() => loggerFactory.GetLogger(typeof(LegacyAuthenticationMiddleware)));
        }

        private ILogger Logger => _lazyLogger.Value;

        /// <inheritdoc />
        public async Task InvokeAsync(HttpContext context)
        {
            string token = null;
            var authHeader = context.Request.Headers[AuthorizationHeaderName].FirstOrDefault();

            if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith(BearerAuthPrefix, StringComparison.OrdinalIgnoreCase))
            {
                token = authHeader.Substring(BearerAuthPrefix.Length).Trim();
            }

            if (string.IsNullOrEmpty(token))
            {
                await _next.Invoke(context);
                return;
            }

            try
            {
                var jwtToken = await _authTokenConverter.ConvertAsync(token);
                context.Request.Headers[AuthorizationHeaderName] = $"{BearerAuthPrefix}{jwtToken}";
            }
            catch (LegacyAuthTokenConversionException ex)
            {
                // This exception is only thrown when a legacy access token has been confirmed but
                // is invalid or expired for some reason. We need to respond with Unauthorized in
                // this case.
                Logger.Warning($"Failed to convert legacy access token ({token})", ex);
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                context.Response.HttpContext.Features.Get<IHttpResponseFeature>().ReasonPhrase = ex.ReasonPhrase;
                return;
            }
            catch (Exception ex)
            {
                Logger.Error($"Exception caught while attempting to convert a legacy access token ({token})", ex);
                // Let this continue through because the token could still be handled by downstream
                // middleware.
            }

            await _next.Invoke(context);
        }
    }
}
