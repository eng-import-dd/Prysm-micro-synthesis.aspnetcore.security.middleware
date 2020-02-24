using System;
using Newtonsoft.Json;

namespace Synthesis.AspNetCore.Security.Middleware.Identity
{
    internal class PolicyUserResponse
    {
        [JsonProperty(PropertyName = "refresh_token")]
        public string RefreshToken { get; set; }

        [JsonProperty(PropertyName = "token_type")]
        public string TokenType { get; set; }

        [JsonProperty(PropertyName = "access_token")]
        public string AccessToken { get; set; }

        [JsonProperty(PropertyName = "user_id")]
        public Guid UserId { get; set; }

        [JsonProperty(PropertyName = "account_id")]
        public Guid? AccountId { get; set; }

        [JsonProperty(PropertyName = "expires_in")]
        public int ExpiresIn { get; set; }

        [JsonProperty(PropertyName = "result_code")]
        public AuthenticateUserResponseResultCode ResultCode { get; set; }

        [JsonProperty(PropertyName = "error_description")]
        public string ErrorDescription { get; set; }

        [JsonProperty(PropertyName = "error")]
        public ErrorCode ErrorCode { get; set; }
    }
}
