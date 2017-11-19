using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Xml;

namespace TodoSPA
{
    public class CustomJwtSecurityTokenHandler : JwtSecurityTokenHandler
    {
        public override bool CanWriteToken
        {
            get
            {
                return true;
            }
        }

        public override bool CanValidateToken
        {
            get
            {
                return true;
            }
        }

        public override SecurityKeyIdentifierClause CreateSecurityTokenReference(SecurityToken token, bool attached)
        {
            return base.CreateSecurityTokenReference(token, attached);
        }

        public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            return base.CreateToken(tokenDescriptor);
        }

        public override SecurityToken ReadToken(string tokenString)
        {
            return base.ReadToken(tokenString);
        }

        public override SecurityToken ReadToken(XmlReader reader)
        {
            return base.ReadToken(reader);
        }

        public override ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            var validTokenResult =  base.ValidateToken(securityToken, validationParameters, out SecurityToken securityTokenParam);
            validatedToken = securityTokenParam;
            return validTokenResult;
        }

        public override bool CanReadKeyIdentifierClause(XmlReader reader)
        {
            return base.CanReadKeyIdentifierClause(reader);
        }

        public override bool CanReadToken(string tokenString)
        {
            return base.CanReadToken(tokenString);
        }

        public override bool CanReadToken(XmlReader reader)
        {
            return base.CanReadToken(reader);
        }

        public override bool CanWriteKeyIdentifierClause(SecurityKeyIdentifierClause securityKeyIdentifierClause)
        {
            return base.CanWriteKeyIdentifierClause(securityKeyIdentifierClause);
        }

        protected override string CreateActorValue(ClaimsIdentity actor)
        {
            return base.CreateActorValue(actor);
        }

        protected override ClaimsIdentity CreateClaimsIdentity(JwtSecurityToken jwt, string issuer, TokenValidationParameters validationParameters)
        {
            return base.CreateClaimsIdentity(jwt, issuer, validationParameters);
        }

        public override JwtSecurityToken CreateToken(string issuer = null, string audience = null, ClaimsIdentity subject = null, DateTime? notBefore = null, DateTime? expires = null, SigningCredentials signingCredentials = null, SignatureProvider signatureProvider = null)
        {
            return base.CreateToken(issuer, audience, subject, notBefore, expires, signingCredentials, signatureProvider);
        }

        protected override void DetectReplayedToken(SecurityToken token)
        {
            base.DetectReplayedToken(token);
        }

        public override string[] GetTokenTypeIdentifiers()
        {
            return base.GetTokenTypeIdentifiers();
        }

        public override void LoadCustomConfiguration(XmlNodeList nodelist)
        {
            base.LoadCustomConfiguration(nodelist);
        }

        public override SecurityKeyIdentifierClause ReadKeyIdentifierClause(XmlReader reader)
        {
            return base.ReadKeyIdentifierClause(reader);
        }

        public override SecurityToken ReadToken(XmlReader reader, SecurityTokenResolver tokenResolver)
        {
            return base.ReadToken(reader, tokenResolver);
        }

        protected override SecurityKey ResolveIssuerSigningKey(string token, SecurityToken securityToken, SecurityKeyIdentifier keyIdentifier, TokenValidationParameters validationParameters)
        {
            return base.ResolveIssuerSigningKey(token, securityToken, keyIdentifier, validationParameters);
        }

        protected override void ValidateAudience(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            base.ValidateAudience(audiences, securityToken, validationParameters);
        }

        protected override string ValidateIssuer(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            return base.ValidateIssuer(issuer, securityToken, validationParameters);
        }

        protected override void ValidateIssuerSecurityKey(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            base.ValidateIssuerSecurityKey(securityKey, securityToken, validationParameters);
        }

        protected override void ValidateLifetime(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            base.ValidateLifetime(notBefore, expires, securityToken, validationParameters);
        }

        protected override JwtSecurityToken ValidateSignature(string token, TokenValidationParameters validationParameters)
        {
            return base.ValidateSignature(token, validationParameters);
        }

        public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
        {
            return base.ValidateToken(token);
        }

        public override void WriteKeyIdentifierClause(XmlWriter writer, SecurityKeyIdentifierClause securityKeyIdentifierClause)
        {
            base.WriteKeyIdentifierClause(writer, securityKeyIdentifierClause);
        }

        public override string WriteToken(SecurityToken token)
        {
            return base.WriteToken(token);
        }

        public override void WriteToken(XmlWriter writer, SecurityToken token)
        {
            base.WriteToken(writer, token);
        }

    }
}