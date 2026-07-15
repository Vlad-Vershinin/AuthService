# JWTSimple 🔑

JWTSimple is a lightweight authentication and authorization library for .NET 8+ applications.

## Features

- JWT authentication with issuer, audience, and token lifetime support
- Refresh token generation and validation
- Secure password hashing
- Simple dependency injection (DI) registration
- Support for custom user identifier types (e.g., Guid)

---

## 🚀 Installation

```bash
dotnet add package JWTSimple --version 1.0.0
```

---

## Quick Start

### 1. Configure JWT

```csharp
using JWTSimple.Extensions;
using JWTSimple.Models;

var builder = WebApplication.CreateBuilder(args);

// 1. Configure JWT settings
var jwtOptions = new JwtOptions
{
    SecretKey = Environment.GetEnvironmentVariable("JWT_SECRET")
        ?? "super-secret-key-that-must-be-very-long-32-characters!",
    Issuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? "MyJWTSimple",
    Audience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") ?? "MyApps",
    ExpiryInMinutes = 15 // Short-lived access token
};

// 2. Register JWTSimple dependencies (specify your user ID type)
builder.Services.AddCustomAuth<Guid>(jwtOptions);

builder.Services.AddControllers();

var app = builder.Build();

// 3. Enable authentication and authorization middleware
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.Run();
```

### 2. Implement the User Model

```csharp
using System.Security.Claims;
using JWTSimple.Interfaces;
using JWTSimple.Models;

public class AppUser : IAuthUser<Guid>, IEmailAuthenticatable
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Role { get; set; } = "User";

    // IAuthUser property: unique user identity (Email)
    public string Identity
    {
        get => Email;
        set => Email = value;
    }

    // IAuthUser property: custom claims embedded into the JWT
    public IEnumerable<Claim> CustomClaims => new List<Claim>
    {
        new Claim(ClaimTypes.Role, Role)
    };

    // Refresh tokens stored in the database
    public List<RefreshToken> RefreshTokens { get; set; } = new();
}
```

### 3. Authentication Example

```csharp
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using JWTSimple.Interfaces;
using JWTSimple.Models;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IPasswordHasher _passwordHasher;
    private readonly IJwtTokenService<Guid> _jwtService;
    private readonly JwtOptions _jwtOptions;

    // Replace with your DbContext or Repository in a real application
    private static readonly List<AppUser> MockUserDatabase = new();

    public AuthController(
        IPasswordHasher passwordHasher,
        IJwtTokenService<Guid> jwtService,
        JwtOptions jwtOptions)
    {
        _passwordHasher = passwordHasher;
        _jwtService = jwtService;
        _jwtOptions = jwtOptions;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        // 1. Find the user (database lookup in a real project)
        var user = MockUserDatabase.FirstOrDefault(u => u.Email == request.Email);
        if (user == null)
            return Unauthorized("Invalid email or password");

        // 2. Verify password hash
        var isPasswordValid = _passwordHasher.VerifyPassword(request.Password, user.PasswordHash);
        if (!isPasswordValid)
            return Unauthorized("Invalid email or password");

        // 3. Generate a new token pair
        var accessToken = _jwtService.GenerateToken(user, _jwtOptions);
        var refreshTokenValue = _jwtService.GenerateRefreshToken();

        // 4. Store the refresh token (and persist it to the database)
        var refreshToken = new RefreshToken
        {
            Token = refreshTokenValue,
            ExpiresAt = DateTime.UtcNow.AddDays(30)
        };
        user.RefreshTokens.Add(refreshToken);

        return Ok(new AuthResponse(accessToken, refreshTokenValue));
    }

    [HttpPost("refresh")]
    public IActionResult Refresh([FromBody] RefreshRequest request)
    {
        try
        {
            // 1. Extract claims from the expired access token
            var principal = _jwtService.GetPrincipalFromExpiredToken(request.AccessToken, _jwtOptions.SecretKey);
            var userIdString = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userIdString) || !Guid.TryParse(userIdString, out var userId))
                return Unauthorized("Invalid token");

            // 2. Find the user
            var user = MockUserDatabase.FirstOrDefault(u => u.Id == userId);
            if (user == null)
                return Unauthorized("User not found");

            // 3. Validate the refresh token
            var savedToken = user.RefreshTokens.FirstOrDefault(t => t.Token == request.RefreshToken);
            if (savedToken == null || savedToken.IsExpired)
                return Unauthorized("Invalid or expired refresh token");

            // 4. Generate a new token pair
            var newAccessToken = _jwtService.GenerateToken(user, _jwtOptions);
            var newRefreshTokenValue = _jwtService.GenerateRefreshToken();

            // 5. Rotate the refresh token
            user.RefreshTokens.Remove(savedToken);
            user.RefreshTokens.Add(new RefreshToken
            {
                Token = newRefreshTokenValue,
                ExpiresAt = DateTime.UtcNow.AddDays(30)
            });

            return Ok(new AuthResponse(newAccessToken, newRefreshTokenValue));
        }
        catch
        {
            return Unauthorized("Failed to refresh token");
        }
    }
}

// DTO models
public record LoginRequest(string Email, string Password);
public record RefreshRequest(string AccessToken, string RefreshToken);
public record AuthResponse(string AccessToken, string RefreshToken);
```

---

## Configuration

The library uses the following `JwtOptions` class:

```csharp
public class JwtOptions
{
    public string SecretKey { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public int ExpiryInMinutes { get; set; } = 15;
}
```

**Important:**

- `SecretKey` must be at least **32 characters** long.

---

## Architecture & Core Components

- `IPasswordHasher` — password hashing and verification
- `IJwtTokenService<TId>` — JWT and refresh token generation
- `JwtOptions` — JWT configuration
- `RefreshToken` — refresh token model

---

## License

This project is licensed under the MIT License.