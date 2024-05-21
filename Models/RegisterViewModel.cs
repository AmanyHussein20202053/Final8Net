using System.ComponentModel.DataAnnotations;

namespace Final8Net.Models
{
    public class RegisterViewModel
    {
        public required string FirstName { get; set; }

        public required string LastName { get; set; }

        public required string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public required string Password { get; set; }

        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public required string ConfirmPassword { get; set; }
        //public required string StatusCode { get; set; }
    }
    
}
