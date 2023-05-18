using extranlLoginAPI.Context;
using extranlLoginAPI.Interfaces;
using extranlLoginAPI.Context.Models;

namespace extranlLoginAPI.Services
{
    public class AccountService : IAccountService
    {
        private readonly AppDbcontext _dbContext;

        public AccountService(AppDbcontext dbContext)
        {
            _dbContext = dbContext;
        }

        public PasswordResetToken GetPasswordResetTokenByUserId(string userId)
        {
            var token = _dbContext.PasswordResetTokens.FirstOrDefault(t => t.UserId == userId);

            return token;
        }

        public void SavePasswordResetToken(PasswordResetToken passwordResetToken)
        {
            _dbContext.PasswordResetTokens.Add(passwordResetToken);

            _dbContext.SaveChanges();
        }
    }
}
