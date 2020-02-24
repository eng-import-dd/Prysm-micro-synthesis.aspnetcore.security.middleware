using System;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Synthesis.Http;
using Synthesis.Http.Extensions;
using Synthesis.Http.Microservice.Constants;
using Synthesis.Policy.Models;
using Synthesis.PolicyEvaluator;
using Synthesis.TenantService.InternalApi.Constants;
using static Synthesis.AspNetCore.Security.Middleware.AuthConstants;
using ClaimTypes = Synthesis.Authentication.Jwt.ClaimTypes;

namespace Synthesis.AspNetCore.Security.Middleware
{
    public class ImpersonateTenantMiddleware
    {
        public const string ImpersonateTenantOperationName = "administration:" + HeaderKeys.ImpersonateTenant;

        private readonly IPolicyEvaluator _policyEvaluator;
        private readonly IHttpClient _httpClient;
        private readonly string _tenantUrl;
        private readonly RequestDelegate _next;
        
        public ImpersonateTenantMiddleware(RequestDelegate next, IPolicyEvaluator policyEvaluator, IHttpClient httpClient, string tenantUrl)
        {
            _policyEvaluator = policyEvaluator;
            _httpClient = httpClient;
            _tenantUrl = tenantUrl.TrimEnd('/');
            _next = next;
        }

        /// <inheritdoc />
        public async Task InvokeAsync(HttpContext context)
        {
            if (!(context.User is ClaimsPrincipal principal))
            {
                await _next.Invoke(context);
                return;
            }

            if (!context.Request.Headers.ContainsKey(HeaderKeys.ImpersonateTenant))
            {
                await _next.Invoke(context);
                return;
            }

            var tenantToImpersonate = context.Request.Headers[HeaderKeys.ImpersonateTenant];
            if (!string.IsNullOrEmpty(tenantToImpersonate) && Guid.TryParse(tenantToImpersonate, out Guid tenantId))
            {
                var evaluationContext = new PolicyEvaluationContext(principal, PermissionType.Operation, ImpersonateTenantOperationName);
                var scope = await _policyEvaluator.EvaluateAsync(evaluationContext, CancellationToken.None);
                if (scope != PermissionScope.Allow)
                {
                    context.Response.StatusCode = 403;
                    context.Response.HttpContext.Features.Get<IHttpResponseFeature>().ReasonPhrase = "The authenticated user is not allowed to impersonate any tenant.";
                    return;
                }

                var authHeaderParts = context.Request.Headers[AuthorizationHeaderName].First().Split(' ');

                var impersonationAllowedRoute = string.Format(Routing.TenantImpersonationAllowedFormat, tenantId);
                var response = await _httpClient.GetWithJsonAsync($"{_tenantUrl}{impersonationAllowedRoute}", authHeaderParts[1]);

                if (!response.IsSuccessStatusCode)
                {
                    context.Response.StatusCode = (int)response.StatusCode;
                    context.Response.HttpContext.Features.Get<IHttpResponseFeature>().ReasonPhrase = response.ReasonPhrase;
                    return;
                }

                principal.AddIdentity(new ClaimsIdentity(Enumerable.Repeat(new Claim(ClaimTypes.ImpersonateTenant, tenantId.ToString()), 1)));
            }

            await _next.Invoke(context);
        }
    }
}