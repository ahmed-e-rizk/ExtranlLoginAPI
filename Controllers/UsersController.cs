using extranlLoginAPI.Interfaces;
using extranlLoginAPI.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using extranlLoginAPI.Context;
using extranlLoginAPI.Context.Models;
using extranlLoginAPI.Entities;
using extranlLoginAPI.Interfaces;
using Swashbuckle.AspNetCore.Annotations;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Security.Cryptography.Xml;

namespace QuraanAPI.Controllers
{
    [AllowAnonymous]
    public class UsersController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly AppDbcontext _dbContext;
        private readonly IAccountService _accountService;
        private readonly IMailService _mailService;
        private readonly ITokenService _tokenService;
        private readonly IConfiguration _configuration;

        public UsersController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            AppDbcontext dbContext,
            IAccountService accountService,
            IMailService mailService,
            ITokenService tokenService,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _dbContext = dbContext;
            _accountService = accountService;
            _mailService = mailService;
            _tokenService = tokenService;
            _configuration = configuration;
        }

        [AllowAnonymous]
        [HttpPost("Signup")]
        [Produces("application/json")]
        [SwaggerResponse(200, "The user was signed up", typeof(ApiResponse))]
        public async Task<JsonResult> Signup(SignUpInput Input)
        {
            if (!ModelState.IsValid)
                return new JsonResult(new
                {
                    Status = false,
                    Message = ModelState.FirstOrDefault().Value?.Errors.FirstOrDefault()?.ErrorMessage,
                    result = new { }
                });

            var user = new IdentityUser
            {
                UserName = Input.Email,
                Email = Input.Email
            };

            var signedinUser = await _userManager.FindByEmailAsync(user.Email);
            if (signedinUser != null )
                return new JsonResult(new { Status = false, Message = "User already signed up", result = new { } });

            // Sign up user
            try
            {
                IdentityResult result;
                if (signedinUser != null )
                {
                    var newToken = await _userManager.GeneratePasswordResetTokenAsync(signedinUser);
                    result = await _userManager.ResetPasswordAsync(signedinUser, newToken, Input.Password);
                    _dbContext.Users.Update(signedinUser);
                    _dbContext.SaveChanges();

                    if (!result.Succeeded)
                        return new JsonResult(new { Status = false, Message = result.Errors.FirstOrDefault()?.Description, result = new { } });

                    // generate token here
                    var jwtToken = _tokenService.BuildToken(_configuration["Jwt:Key"],
                        _configuration["Jwt:Issuer"], signedinUser);

                    return new JsonResult(new
                    {
                        Status = true,
                        Message = "User signed up successfully",
                        result = new
                        {
                            Token = jwtToken.Token,
                            Expiration = jwtToken.ExpirationDate
                        }
                    });
                }
                else
                {
                    result = await _userManager.CreateAsync(user, Input.Password);

                    if (!result.Succeeded)
                        return new JsonResult(new { Status = false, Message = result.Errors.FirstOrDefault()?.Description, result = new { } });
                    // generate token here
                    var jwtToken = _tokenService.BuildToken(_configuration["Jwt:Key"],
                        _configuration["Jwt:Issuer"], user);

                    return new JsonResult(new
                    {
                        Status = true,
                        Message = "User signed up successfully",
                        result = new
                        {
                            Token = jwtToken.Token,
                            Expiration = jwtToken.ExpirationDate
                        }
                    });
                }
            }
            catch (Exception e)
            {
                return new JsonResult(new { Status = false, Message = e.Message, result = new { } });
            }
        }

        [AllowAnonymous]
        [HttpPost("Signin")]
        [Produces("application/json")]
        [SwaggerResponse(200, "The user was signed in", typeof(ApiResponseWithToken))]
        public async Task<JsonResult> Signin(SignInInput Input)
        {
            if (!ModelState.IsValid)
                return new JsonResult(new
                {
                    Status = false,
                    Message = ModelState.FirstOrDefault().Value?.Errors.FirstOrDefault()?.ErrorMessage
                });

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
                return new JsonResult(new { Status = false, Message = "User is not signed up" });

            var result = await _signInManager.CheckPasswordSignInAsync(user, Input.Password, false);
            if (!result.Succeeded)
                return new JsonResult(new { Status = false, Message = "Signing in user failed" });

            // generate token here
            var token = _tokenService.BuildToken(_configuration["Jwt:Key"],
                _configuration["Jwt:Issuer"], user);

            return new JsonResult(new
            {
                Status = true,
                Message = "User signed in successfully",
                result = new
                {
                    Token = token.Token,
                    Expiration = token.ExpirationDate,
                }
            });
        }

        [HttpPatch("DeleteAccount")]
        public async Task<JsonResult> DeleteAccount([Required] string UserToken)
        {
            if (string.IsNullOrEmpty(UserToken))
            {
                return new JsonResult(new
                {
                    Status = false,
                    Message = "Please enter a valid token",
                    result = new { }
                });
            }

            var claims = _tokenService.GetClaimsFromToken(_configuration["Jwt:Key"], _configuration["Jwt:Issuer"], UserToken);
            if (claims == null)
                return new JsonResult(new { Status = false, message = "Please provide user token", result = new { } });

            var user = _dbContext.Users.FirstOrDefault(e => e.Email == claims.FindFirstValue(ClaimTypes.Email));
            if (user == null )
                return new JsonResult(new { Status = false, message = "User is already deleted", result = new { } });

            try
            {
               
                _dbContext.Users.Remove(user);
                _dbContext.SaveChanges();

                return new JsonResult(new { Status = true, Message = "User deleted successfully", result = new { } });
            }
            catch (Exception e)
            {
                return new JsonResult(new { Status = false, Message = e.Message, result = new { } });
            }
        }

       
        [AllowAnonymous]
        [HttpPost("ForgotPassword")]
        [Produces("application/json")]
        [SwaggerResponse(200, "Password reset email got sent successfully", typeof(ApiResponse))]
        public async Task<JsonResult> ForgotPassword([Required][EmailAddress] string email)
        {
            if (!ModelState.IsValid)
                return new JsonResult(new
                {
                    Status = false,
                    Message = ModelState.FirstOrDefault().Value?.Errors.FirstOrDefault()?.ErrorMessage
                });

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return new JsonResult(new { Status = false, Message = "User can not be found" });

            PasswordResetToken passwordResetToken;
            passwordResetToken = _accountService.GetPasswordResetTokenByUserId(user.Id);

            if (passwordResetToken != null)
            {
                // remake the token
                passwordResetToken.Token = GeneratePasswordResetToken.GenerateRandomNo();
                passwordResetToken.ExpirationDate = DateTime.Now.AddHours(5);
            }
            else
            {
                passwordResetToken = new PasswordResetToken
                {
                    Token = GeneratePasswordResetToken.GenerateRandomNo(),
                    ExpirationDate = DateTime.Now.AddHours(5),
                    User = user
                };

                _dbContext.PasswordResetTokens.Add(passwordResetToken);
            }
            _dbContext.SaveChanges();

            var body = string.Format(@"Hey {0}, Your token for password reset is {1}.", passwordResetToken.Token);

            var emailRequest = new MailRequest
            {
                ToEmail = email,
                Subject = "Password Reset",
                Body = body
            };

            _mailService.SendEmail(emailRequest);
            return new JsonResult(new { Status = true, Message = "Password reset email got sent successfully" });
        }

        [AllowAnonymous]
        [HttpPost("VerifyPasswordResetToken")]
        [Produces("application/json")]
        [SwaggerResponse(200, "Password reset token is correct", typeof(ApiResponse))]
        public async Task<JsonResult> VerifyPasswordResetToken(
            [Required][EmailAddress] string email, [Required] string token)
        {
            if (!ModelState.IsValid)
                return new JsonResult(new
                {
                    Status = false,
                    Message = ModelState.FirstOrDefault().Value?.Errors.FirstOrDefault()?.ErrorMessage
                });

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return new JsonResult(new { Status = false, Message = "User can not be found" });

            var resetToken = _dbContext.PasswordResetTokens.FirstOrDefault(t => t.UserId == user.Id);
            if (resetToken?.Token != token)
                return new JsonResult(new { Status = false, Message = "Incorrect token" });

            var dateNow = DateTime.Now;
            if (DateTime.Compare(dateNow, resetToken.ExpirationDate) > 0)
                return new JsonResult(new { Status = false, Message = "Token expired" });

            return new JsonResult(new { Status = true, Message = "Password reset token is correct" });
        }

        [AllowAnonymous]
        [HttpPost("UpdatePassword")]
        [Produces("application/json")]
        [SwaggerResponse(200, "Password updated successfully", typeof(ApiResponse))]
        public async Task<JsonResult> UpdatePassword(UpdatePasswordInput Input)
        {
            if (!ModelState.IsValid)
                return new JsonResult(new
                {
                    Status = false,
                    Message = ModelState.FirstOrDefault().Value?.Errors.FirstOrDefault()?.ErrorMessage
                });

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user is null)
                return new JsonResult(new { Status = false, Message = "User can not be found" });

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var result = await _userManager.ResetPasswordAsync(user, token, Input.Password);
            if (!result.Succeeded)
                return new JsonResult(new { Status = false, Message = result.Errors.FirstOrDefault()?.Description });

            return new JsonResult(new { Status = true, Message = "Password updated successfully" });
        }

        [AllowAnonymous]
        [HttpPost("ResendPasswordResetToken")]
        [Produces("application/json")]
        [SwaggerResponse(200, "Password reset email got sent successfully", typeof(ApiResponse))]
        public async Task<JsonResult> ResendPasswordResetToken([Required][EmailAddress] string email)
        {
            if (!ModelState.IsValid)
                return new JsonResult(new
                {
                    Status = false,
                    Message = ModelState.FirstOrDefault().Value?.Errors.FirstOrDefault()?.ErrorMessage
                });

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return new JsonResult(new { Status = false, Message = "User can not be found" });

            PasswordResetToken passwordResetToken;
            passwordResetToken = _accountService.GetPasswordResetTokenByUserId(user.Id);

            if (passwordResetToken != null)
            {
                // remake the token
                passwordResetToken.Token = GeneratePasswordResetToken.GenerateRandomNo();
                passwordResetToken.ExpirationDate = DateTime.Now;
            }
            else
            {
                passwordResetToken = new PasswordResetToken
                {
                    Token = GeneratePasswordResetToken.GenerateRandomNo(),
                    ExpirationDate = DateTime.Now.AddHours(5),
                    User = user
                };

                _dbContext.PasswordResetTokens.Add(passwordResetToken);
            }
            _dbContext.SaveChanges();

            var body = string.Format(@"Hey {0}, Your token for password reset is {1}.",
                passwordResetToken.Token);

            var emailRequest = new MailRequest
            {
                ToEmail = email,
                Subject = "Password Reset",
                Body = body
            };

            _mailService.SendEmail(emailRequest);
            return new JsonResult(new { Status = true, Message = "Password reset email got sent successfully" });
        }

        [AllowAnonymous]
        [HttpGet("ExternalLogin")]
        [Produces("application/json")]
        public IActionResult ExternalLogin(string? AuthScheme)
        {
            var redirectUrl = Url.Action("ExternalLoginCallback", "Users");

            if (string.IsNullOrEmpty(AuthScheme))
                return new JsonResult(new { Status = false, Message = "Please Provide an external signup service name for example: Google or Facebook", result = new { } });

            string oauthScheme;
            if (AuthScheme.ToLower() == "facebook")
                oauthScheme = FacebookDefaults.AuthenticationScheme;
            else if (AuthScheme.ToLower() == "google")
                oauthScheme = GoogleDefaults.AuthenticationScheme;
            else
                return new JsonResult(new { Status = false, Message = "Please Provide an external signup service name for example: Google or Facebook", result = new { } });

            var properties = _signInManager
                .ConfigureExternalAuthenticationProperties(oauthScheme, redirectUrl);

            return Challenge(properties, oauthScheme);
        }

        [AllowAnonymous]
        [HttpGet("ExternalLoginCallback")]
        [Produces("application/json")]
        public async Task<JsonResult> ExternalLoginCallback(string? remoteError = null)
        {
            if (remoteError != null)
            {
                return new JsonResult(new
                {
                    Status = false,
                    Message = $"Error from external provider: {remoteError}",
                    Result = new { }
                });
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return new JsonResult(new
                {
                    Status = false,
                    Message = "Failed to authenticate user",
                    Result = new { }
                });
            }

            // Remove external cookies after successful log in
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (email == null)
                return new JsonResult(new { Statue = false, Message = "Failed to authenticate user", Result = new { } });

            // Figure out if the user is signed in with google before
            var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
            if (user != null)
            {
                var token = _tokenService.BuildToken(_configuration["Jwt:Key"],
                    _configuration["Jwt:Issuer"], user);

                return new JsonResult(new
                {
                    Status = true,
                    Message = "User signed in successfully",
                    Result = new
                    {
                        Token = token.Token,
                        Expiration = token.ExpirationDate
                    }
                });
            }
            else
            {
                user = new IdentityUser
                {
                    UserName = info.Principal.FindFirstValue(ClaimTypes.Email),
                    Email = info.Principal.FindFirstValue(ClaimTypes.Email),
                };

                await _userManager.CreateAsync(user);
                await _userManager.AddLoginAsync(user, info);
                if (!await _signInManager.CanSignInAsync(user))
                {
                    return new JsonResult(new
                    {
                        Status = false,
                        Message = "Failed to authenticate user",
                        Result = new { }
                    });
                }

                var token = _tokenService.BuildToken(_configuration["Jwt:Key"],
                    _configuration["Jwt:Issuer"], user);

                return new JsonResult(new
                {
                    Status = true,
                    Message = "User signed in successfully",
                    Result = new
                    {
                        Token = token.Token,
                        Expiration = token.ExpirationDate
                    }
                });
            }
        }
    }
}