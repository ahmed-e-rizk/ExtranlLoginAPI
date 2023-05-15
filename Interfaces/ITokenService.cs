using extranlLoginAPI.Entities;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace extranlLoginAPI.Interfaces
{
    public interface ITokenService
    {
        JwtToken BuildToken(string key, string issuer, IdentityUser user);
        ClaimsPrincipal? GetClaimsFromToken(string key, string issuer, string token);
    }
}
