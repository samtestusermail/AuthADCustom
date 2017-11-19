using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Threading.Tasks;

namespace TodoSPA
{
    public class CustomIOAuthBearerAuthenticationProvider : IOAuthBearerAuthenticationProvider
    {
        public Task ApplyChallenge(OAuthChallengeContext context)
        {
            return Task.FromResult<object>(null);
        }

        public Task RequestToken(OAuthRequestTokenContext context)
        {
            string token = context.Request.Headers["Authorization"];
            if (!string.IsNullOrEmpty(token))
            {
                context.Token = token.Replace("Bearer ", "");
            }
            return Task.FromResult<object>(null);
        }

        public Task ValidateIdentity(OAuthValidateIdentityContext context)
        {
            return Task.FromResult<object>(null);
        }
    }
}