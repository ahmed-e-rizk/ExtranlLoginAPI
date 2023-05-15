using System.ComponentModel.DataAnnotations;

namespace extranlLoginAPI.Entities
{
    public class SignInInput
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
