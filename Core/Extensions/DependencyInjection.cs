using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Core.Interfaces;
using Core.Models;
using Core.Services;

namespace Core.Extensions;

public static class DependencyInjection
{
    public static IServiceCollection AddCustomAuth<TId>(
        this IServiceCollection services,
        JwtOptions options) where TId : IEquatable<TId>
    {
        if (options == null)
            throw new ArgumentNullException(nameof(options));

        if (string.IsNullOrWhiteSpace(options.SecretKey) || options.SecretKey.Length < 32)
            throw new ArgumentException("Secret key is invalid.");

        services.AddSingleton(options);

        services.AddScoped<IPasswordHasher, PasswordHasher>();
        services.AddScoped<IJwtTokenService<TId>, JwtTokenService<TId>>();

        services.AddAuthentication(authOptions =>
        {
            authOptions.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            authOptions.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(jwtBearerOptions =>
        {
            jwtBearerOptions.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.SecretKey)),

                ValidateIssuer = !string.IsNullOrEmpty(options.Issuer),
                ValidIssuer = options.Issuer,

                ValidateAudience = !string.IsNullOrEmpty(options.Audience),
                ValidAudience = options.Audience,

                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(5)
            };
        });

        return services;
    }
}
