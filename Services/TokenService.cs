using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using UserAuth.Helpers; 

namespace UserAuth.Services
{
    public class TokenService
    {
        private readonly JwtOptions _options;
        private readonly SigningCredentials _creds; 

        public TokenService(IOptions<JwtOptions> options)
        {
            _options = options.Value; 
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.Key));
            _creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256); 
        }

        public string CreateAccessToken(IEnumerable<Claim> claims)
        {
            var jwt = new JwtSecurityToken(
                issuer: _options.Issuer,
                audience: _options.Audience,
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddMinutes(_options.AccessTokenMinutes),
                signingCredentials: _creds
            );
            return new JwtSecurityTokenHandler().WriteToken(jwt); 
        }

        public string CreateRefreshToken()
        {
            var bytes = RandomNumberGenerator.GetBytes(32);
            return Convert.ToBase64String(bytes); 
        }

    }
}
