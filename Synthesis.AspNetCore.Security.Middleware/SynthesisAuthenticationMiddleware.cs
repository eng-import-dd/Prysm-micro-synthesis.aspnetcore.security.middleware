using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Synthesis.Authentication;
using Synthesis.Http.Microservice.Constants;
using Synthesis.Logging;
using static Synthesis.AspNetCore.Security.Middleware.AuthConstants;

namespace Synthesis.AspNetCore.Security.Middleware
{
    public class SynthesisAuthenticationMiddleware
    {
        private readonly ITokenValidator _tokenValidator;
        private readonly ILogger _logger;
        private readonly RequestDelegate _next;
        /// <inheritdoc />
        public SynthesisAuthenticationMiddleware(
            RequestDelegate next,
            ITokenValidator tokenValidator,
            ILoggerFactory loggerFactory)
        {
            _next = next;
            _tokenValidator = tokenValidator;
            _logger = loggerFactory.GetLogger(this);
        }

        /// <inheritdoc />
        public async Task InvokeAsync(HttpContext context)
        {
            var requestToken = (string)null;
            var authorization = context.Request.Headers[AuthorizationHeaderName].FirstOrDefault();
            if (!string.IsNullOrEmpty(authorization) && authorization.StartsWith(BearerAuthPrefix, StringComparison.OrdinalIgnoreCase))
            {
                requestToken = authorization.Substring(BearerAuthPrefix.Length).Trim();
            }

            if (!string.IsNullOrEmpty(requestToken))
            {
                try
                {
                    var principal = await _tokenValidator.ValidateForSynthesisAnyAsync(requestToken);

                    var extendedClaims = GetExtendedClaims(principal, context.Request.Headers).ToList();
                    if (extendedClaims.Any())
                    {
                        principal.AddIdentity(new ClaimsIdentity(extendedClaims));
                    }

                    context.User = principal;
                }
                catch (SecurityTokenNotYetValidException ex)
                {
                    _logger.Info($"Not yet valid security token used while calling route {context.Request.Path}: {requestToken}", ex);
                }
                catch (SecurityTokenExpiredException ex)
                {
                    _logger.Info($"Expired security token used while calling route {context.Request.Path}: {requestToken}", ex);
                }
                catch (SecurityTokenException ex)
                {
                    _logger.Warning($"Invalid security token provided while calling route {context.Request.Path}: {requestToken}", ex);
                }
                catch (Exception ex)
                {
                    _logger.Error($"Failed to validate Bearer token calling route {context.Request.Path}: {requestToken}", ex);
                }
            }

            await _next.Invoke(context);
        }

        public IEnumerable<Claim> GetExtendedClaims(ClaimsPrincipal currentPrincipal, IHeaderDictionary requestHeaders)
        {
            // If this is being called by a service principal (which means there won't be a
            // tenant specified in the JWT), we should check to see if a tenant was passed
            // in the header. If so, let's use that one because we implicitly trust
            // microservices to be making requests on behalf of an authorized tenant user.

            if (!currentPrincipal.IsServicePrincipal())
            {
                yield break;
            }

            if (requestHeaders.ContainsKey(HeaderKeys.Tenant) && Guid.TryParse(requestHeaders[HeaderKeys.Tenant], out var tenantId))
            {
                yield return new Claim(Authentication.Jwt.ClaimTypes.Tenant, tenantId.ToString());
            }
        }
    }
}