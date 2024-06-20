using System.ComponentModel.DataAnnotations;

namespace Final8Net.Models
{
    public class FactorViewModel
    {

        [Required(ErrorMessage = "Verification code is required.")]
        public required string Code { get; set; }

        [Display(Name = "Remember Browser")]
        public bool RememberBrowser { get; set; }
    }
}