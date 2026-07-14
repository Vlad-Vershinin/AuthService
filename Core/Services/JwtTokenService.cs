using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Core.Interfaces;
using Core.Models;

namespace Core.Services;

public class JwtTokenService<TId> : IJwtTokenService<TId> where TId : IEquatable<TId>
{
    public string GenerateToken(IAuthUser<TId> user, JwtOptions options)
    {
        if (user == null)
            throw new ArgumentNullException(nameof(user));

        if (options == null)
            throw new ArgumentNullException(nameof(options));

        if (string.IsNullOrWhiteSpace(options.SecretKey) || options.SecretKey.Length < 32)
            throw new ArgumentException("Secret key must be at least 32 characters long.", nameof(options.SecretKey));

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()!),
            new Claim(ClaimTypes.Name, user.Identity)
        };

        if (user.CustomClaims != null)
        {
            claims.AddRange(user.CustomClaims);
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.SecretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: options.Issuer,
            audience: options.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(options.ExpiryInMinutes),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
