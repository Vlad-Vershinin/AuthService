using System.Security.Claims;

namespace Core.Models;

public interface IAuthUser<TId> where TId : IEquatable<TId>
{
    TId Id { get; set; }
    string Identity { get; set; }
    string PasswordHash { get; set; }

    IEnumerable<Claim> CustomClaims { get; }
}
