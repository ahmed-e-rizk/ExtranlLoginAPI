using extranlLoginAPI.Context.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace extranlLoginAPI.Context
{
    public class AppDbcontext :   IdentityDbContext<IdentityUser>
    {
        public AppDbcontext(DbContextOptions<AppDbcontext> options)
          : base(options) { }
        public virtual DbSet<PasswordResetToken> PasswordResetTokens { get; set; } = null!;

    }
}
