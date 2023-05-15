using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace extranlLoginAPI.Context.Models
{
    [Index(nameof(UserId), IsUnique = true)]
    public class PasswordResetToken
    {
        public int PasswordResetTokenId { get; set; }
        public string Token { get; set; }
        public DateTime ExpirationDate { get; set; }
        public string UserId { get; set; }
        public IdentityUser User { get; set; }
    }
}
