using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace extranlLoginAPI.Entities
{
    public class SignUpInput
    {
        [Required]
        public string FullName { get; set; } = string.Empty;
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        //[Required]
        //[DefaultValue(false)]
        //public bool IsAgreeWithTerms { get; set; }
    }
}
