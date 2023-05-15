using extranlLoginAPI.Context.Models;

namespace extranlLoginAPI.Interfaces
{
    public interface IAccountService
    {
        void SavePasswordResetToken(PasswordResetToken passwordResetToken);
        PasswordResetToken GetPasswordResetTokenByUserId(string userId);
    }
}
