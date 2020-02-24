using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Synthesis.Cache;
using Synthesis.Configuration;
using Synthesis.Http;
using Synthesis.AspNetCore.Security.Middleware.Identity;
using Synthesis.Serialization;
using Synthesis.Threading.Tasks;
using static Synthesis.AspNetCore.Security.Middleware.AuthConstants;

namespace Synthesis.AspNetCore.Security.Middleware
{
    /// <summary>
    /// Converts a legacy access token (GUID) into a JWT that has been cached by the Cloud Shim.
    /// A legacy access token is obtained by older clients that authenticate using the old cloud
    /// endpoints instead of with the newer OAuth-compliant Identity service endpoints.
    /// </summary>
    /// <seealso cref="IAuthTokenConverter" />
    public class LegacyAuthTokenConverter : IAuthTokenConverter
    {
        public const double LegacyTokenTimeoutSeconds = 86400;
        public static readonly TimeSpan LegacyTokenTimeout = TimeSpan.FromSeconds(LegacyTokenTimeoutSeconds);

        private const string AccessTokenPath = "/policy/oauth/access_token";
        private const string DefaultClientId = "1";
        private static readonly int GuidLength = Guid.NewGuid().ToString().Length;

        private readonly ICache _tokenCache;
        private readonly IHttpClient _httpClient;
        private readonly IObjectSerializer _serializer;
        private readonly string _identityUrl;

        public LegacyAuthTokenConverter(
            ICache tokenCache,
            IHttpClient httpClient,
            IObjectSerializer serializer,
            IAppSettingsReader appSettingsReader)
        {
            _tokenCache = tokenCache;
            _httpClient = httpClient;
            _serializer = serializer;
            _identityUrl = appSettingsReader.GetValue<string>("Identity.Url").TrimEnd('/');
        }

        public static string TokenKey(Guid legacyGuid) => $"LegacyToken:{legacyGuid}";

        public static string RefreshTokenKey(Guid legacyGuid) => $"LegacyRefreshToken:{legacyGuid}";

        /// <inheritdoc />
        public async Task<string> ConvertAsync(string token, CancellationToken cancellationToken = new CancellationToken())
        {
            if (token?.Length != GuidLength || !Guid.TryParse(token, out var legacyToken))
            {
                return token;
            }

            // We have a legacy token. At this point we need to attempt to get the real token
            // out of the cache if it exists.
            //
            // If the legacy token is not present in the cache (either expired or not), we
            // need to attempt to get the refresh token out of the cache to request a new JWT.
            //
            // If the refresh token isn't present, we need to return 401 (Unauthorized).
            // 
            // Once we have a JWT (either refreshed or not), we need to set the Authorization
            // header with the JWT so subsequent microservice calls are authenticated.

            var tokenKey = TokenKey(legacyToken);
            var jwtRef = new Reference<string>();
            var jwtTokenExists = await _tokenCache.TryItemGetAsync(tokenKey, jwtRef);
            if (!jwtTokenExists)
            {
                throw new LegacyAuthTokenConversionException($"The legacy token key for {legacyToken} has expired")
                {
                    ReasonPhrase = "Missing access token"
                };
            }

            // Read the JWT and see if it has expired.
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(jwtRef.Value);
            if (DateTime.UtcNow.Add(TimeSpan.FromSeconds(10)) < jwtSecurityToken.ValidTo)
            {
                // It has not expired, conversion successful.
                return jwtRef.Value;
            }

            // The JWT has expired, get the refresh token and use it to get a new access token.
            var refreshTokenKey = RefreshTokenKey(legacyToken);
            var refreshTokenRef = new Reference<string>();
            var refreshTokenExists = await _tokenCache.TryItemGetAsync(refreshTokenKey, refreshTokenRef);
            if (!refreshTokenExists)
            {
                throw new LegacyAuthTokenConversionException($"The refresh token key for legacy token {legacyToken} has expired.")
                {
                    ReasonPhrase = "Missing refresh token"
                };
            }

            // Get the client_id out of the JWT payload.
            var clientId = jwtSecurityToken.Payload.TryGetValue(Authentication.Jwt.ClaimTypes.ClientId, out var tempValue)
                ? tempValue as string ?? DefaultClientId
                : DefaultClientId;

            var response = await RefreshTokenAsync(refreshTokenRef.Value, clientId);
            if (response.ResultCode != AuthenticateUserResponseResultCode.Success)
            {
                throw new LegacyAuthTokenConversionException($"Failed to refresh the legacy access token ({legacyToken}): {response.ResultCode} ({response.ErrorCode}: {response.ErrorDescription})")
                {
                    ReasonPhrase = $"Failed to refresh access token: {response.ResultCode}"
                };
            }

            await _tokenCache.ItemSetAsync(tokenKey, response.AccessToken, LegacyTokenTimeout, CacheCommandOptions.FireAndForget);
            if (!string.IsNullOrEmpty(response.RefreshToken))
            {
                await _tokenCache.ItemSetAsync(refreshTokenKey, response.RefreshToken, LegacyTokenTimeout, CacheCommandOptions.FireAndForget);
            }
            else
            {
                await _tokenCache.KeyExpireAsync(refreshTokenKey, LegacyTokenTimeout, CacheCommandOptions.FireAndForget);
            }

            return response.AccessToken;
        }

        private async Task<PolicyUserResponse> RefreshTokenAsync(string refreshToken, string clientId)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, $"{_identityUrl}{AccessTokenPath}");
            var body = new Dictionary<string, string>
            {
                { "grant_type", "refresh_token" },
                { "refresh_token", refreshToken }
            };

            var basicAuthToken = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:secret"));

            request.Headers.TryAddWithoutValidation(AuthorizationHeaderName, $"Basic {basicAuthToken}");
            request.Content = new FormUrlEncodedContent(body);

            using (var response = await _httpClient.SendAsync(request, CancellationToken.None))
            {
                if (!response.IsSuccessStatusCode)
                {
                    return new PolicyUserResponse { ResultCode = AuthenticateUserResponseResultCode.InvalidLogin };
                }

                var responseStream = await response.Content.ReadAsStreamAsync();
                return await _serializer.DeserializeAsync<PolicyUserResponse>(responseStream);
            }
        }
    }
}