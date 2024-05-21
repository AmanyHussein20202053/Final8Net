using System.ComponentModel.DataAnnotations;

namespace Final8Net.Models
{
    public class LoginViewModel
    {
        public required string Email { get; set; }

        [DataType(DataType.Password)]
        public required string Password { get; set; }
    }
}
