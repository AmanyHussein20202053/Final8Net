using System.ComponentModel.DataAnnotations;

namespace Final8Net.Models
{
    public class AuthViewModel
    {
        [Required(ErrorMessage = "Rewrite the same Email to verify.")]
        [Display(Name = "Email")]
        public required string email {get; set; }
        [Required(ErrorMessage = "Verification code is required.")]
        public required string Code { get; set; }

        [Display(Name = "Remember Browser")]
        public bool RememberBrowser { get; set; }
         
    }
}
