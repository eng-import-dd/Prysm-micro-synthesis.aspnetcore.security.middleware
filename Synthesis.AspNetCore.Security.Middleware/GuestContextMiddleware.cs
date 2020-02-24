using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Synthesis.Guest.ProjectContext.Models;
using Synthesis.Guest.ProjectContext.Services;
using ClaimTypes = Synthesis.Authentication.Jwt.ClaimTypes;
using Microsoft.AspNetCore.Http;

namespace Synthesis.AspNetCore.Security.Middleware
{
    public class GuestContextMiddleware 
    {
        private readonly RequestDelegate _next;
        private readonly IProjectGuestContextService _projectGuestContextService;

        /// <inheritdoc />
        public GuestContextMiddleware(RequestDelegate next, IProjectGuestContextService projectGuestContextService)
        {
            _projectGuestContextService = projectGuestContextService;
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

            var projectGuestContext = await _projectGuestContextService.GetProjectGuestContextAsync();
            if (projectGuestContext == null)
            {
                await _next.Invoke(context);
                return;
            }

            // Add the project guest context claims to the principal.
            principal.AddIdentity(new ClaimsIdentity(ExtractGuestClaims(projectGuestContext)));

            await _next.Invoke(context);
        }

        private static IEnumerable<Claim> ExtractGuestClaims(ProjectGuestContext projectGuestContext)
        {
            yield return new Claim(ClaimTypes.GuestTenant, projectGuestContext.TenantId.ToString());
            yield return new Claim(ClaimTypes.GuestProject, projectGuestContext.ProjectId.ToString());
            yield return new Claim(ClaimTypes.GuestSession, projectGuestContext.GuestSessionId.ToString());
            yield return new Claim(ClaimTypes.GuestState, projectGuestContext.GuestState.ToString());
        }
    }
}