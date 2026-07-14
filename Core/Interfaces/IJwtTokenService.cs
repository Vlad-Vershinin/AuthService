using Core.Models;

namespace Core.Interfaces;

public interface IJwtTokenService<TId> where TId : IEquatable<TId>
{
    string GenerateToken(IAuthUser<TId> user, JwtOptions options);
}
