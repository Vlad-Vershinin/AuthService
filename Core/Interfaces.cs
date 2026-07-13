namespace Core;

public interface IPasswordHasher
{
    string HashPassword(string password);
    bool VerifyPassword(string password, string passwordHash);
}


public interface IJwtTokenService<TId> where TId : IEquatable<TId>
{
    string GenerateToken(IAuthUser<TId> user, string secretKey, string issuer, string audience, int expiryInMinutes);
}