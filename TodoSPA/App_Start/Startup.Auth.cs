using Microsoft.Owin.Security.ActiveDirectory;
using Microsoft.Owin.Security.Jwt;
using Owin;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Web;

namespace TodoSPA
{
    public partial class Startup
    {
        public void ConfigureAuth(IAppBuilder app) {
            string issuerCustomJWT = "issuerCustomJWT";
            string trustedTokenPolicyKey = "401b09eab3c013d4ca54922bb802bec8fd5318192b0a75f201d8b3727429090fb337591abd3e44453b954555b7a0812e1081c39b740293f765eae731f5a65ed1";
            app.UseWindowsAzureActiveDirectoryBearerAuthentication(
            new WindowsAzureActiveDirectoryBearerAuthenticationOptions
            {
                Audience = ConfigurationManager.AppSettings["ida:Audience"],
                Tenant = ConfigurationManager.AppSettings["ida:Tenant"],
            });

            app.UseJwtBearerAuthentication(new Microsoft.Owin.Security.Jwt.JwtBearerAuthenticationOptions()
            {
                //
                AllowedAudiences = new List<string>() { "audCustomJWT" },
                //AuthenticationMode =  Microsoft.Owin.Security.AuthenticationMode.Active ,
                IssuerSecurityTokenProviders = new IIssuerSecurityTokenProvider[]
                {
                    //new X509CertificateSecurityTokenProvider(Issuer, X509CertificateHelper.FindByThumbprint(StoreName.My, StoreLocation.LocalMachine, thumbPrint).First()),
                    new SymmetricKeyIssuerSecurityTokenProvider(issuerCustomJWT, trustedTokenPolicyKey),
                },
                //TokenHandler = new CustomJwtSecurityTokenHandler(),
                //AuthenticationType = DefaultAuthenticationTypes string
                Provider = new CustomIOAuthBearerAuthenticationProvider(),
                //Realm optional string for oauth

                TokenValidationParameters = new System.IdentityModel.Tokens.TokenValidationParameters()
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new InMemorySymmetricSecurityKey(Encoding.UTF8.GetBytes(trustedTokenPolicyKey)),
                    AudienceValidator = CustomAudienceValidator,
                    IssuerValidator = CustomIssueValidator
                }

            });


        }

        private string CustomIssueValidator(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            return issuer;
        }

        private bool CustomAudienceValidator(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {

            return true;
        }
    }
}