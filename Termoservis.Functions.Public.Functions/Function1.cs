using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Termoservis.Functions.Public.Functions
{
    internal static class AppConfiguration
    {
        public static string Auth0Issuer => GetRequiredEnvironmentVariable("AUTH0_ISSUER");

        public static string Auth0Audience => GetRequiredEnvironmentVariable("AUTH0_AUDIENCE");

        private static string GetRequiredEnvironmentVariable(string key)
        {
            var value = Environment.GetEnvironmentVariable(key);
            if (value == null)
                throw new NullReferenceException($"Application configuration invalid for `{key}`");
            return value;
        }
    }

    // ReSharper disable once UnusedMember.Global
    public static class Function1
    {
        [FunctionName("Function1")]
        // ReSharper disable once UnusedMember.Global
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            CancellationToken cancellationToken,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            var authHeader = req.GetAuthorizationHeader();
            var principal = await Security.ValidateTokenAsync(authHeader);
            if (principal == null)
                return new UnauthorizedResult();

            return new OkObjectResult($"Hello, {principal.Identity.Name}.");
        }
    }

    public static class HttpRequestSecurityExtensions
    {
        private const string AuthorizationHeaderKey = "Authorization";

        public static AuthenticationHeaderValue GetAuthorizationHeader(this HttpRequest req)
        {
            if (req == null) throw new ArgumentNullException(nameof(req));

            if (!req.Headers.TryGetValue(AuthorizationHeaderKey, out var authHeader)) 
                return null;

            return AuthenticationHeaderValue.TryParse(authHeader, out var authHeaderValue)
                ? authHeaderValue
                : null;
        }
    }

    public static class Security
    {
        private static readonly IConfigurationManager<OpenIdConnectConfiguration> ConfigurationManager;

        static Security()
        {
            var issuer = AppConfiguration.Auth0Issuer;

            var documentRetriever = new HttpDocumentRetriever {RequireHttps = issuer.StartsWith("https://")};

            ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                $"{issuer}/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(),
                documentRetriever
            );
        }

        public static async Task<ClaimsPrincipal> ValidateTokenAsync(AuthenticationHeaderValue value)
        {
            if (value?.Scheme != "Bearer")
            {
                return null;
            }

            var config = await ConfigurationManager.GetConfigurationAsync(CancellationToken.None);
            var issuer = AppConfiguration.Auth0Issuer;
            var audience = AppConfiguration.Auth0Audience;

            var validationParameter = new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidAudience = audience,
                ValidateAudience = true,
                ValidIssuer = issuer,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
                IssuerSigningKeys = config.SigningKeys
            };

            ClaimsPrincipal result = null;
            var tries = 0;

            while (result == null && tries <= 1)
            {
                try
                {
                    var handler = new JwtSecurityTokenHandler();
                    result = handler.ValidateToken(value.Parameter, validationParameter, out _);
                }
                catch (SecurityTokenSignatureKeyNotFoundException)
                {
                    // This exception is thrown if the signature key of the JWT could not be found.
                    // This could be the case when the issuer changed its signing keys, so we trigger a 
                    // refresh and retry validation.
                    ConfigurationManager.RequestRefresh();
                    tries++;
                }
                catch (SecurityTokenException)
                {
                    return null;
                }
            }

            return result;
        }
    }
}
