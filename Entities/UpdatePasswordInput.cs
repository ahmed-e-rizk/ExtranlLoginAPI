using System.ComponentModel.DataAnnotations;

namespace extranlLoginAPI.Entities
{
    public class UpdatePasswordInput
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and Confirm password are not the same")]
        public string PasswordConfirm { get; set; }
    }
}
