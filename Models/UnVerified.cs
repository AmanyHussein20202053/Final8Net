
using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace Final8Net.Models
{
    public class UnVerified 
    {
        [Key]
        public int id { get; set; }

        public required string Firstname { get; set; }

        public required string Lastname { get; set; }

        public required string Email { get; set; }

        public required string Password { get; set; }

        //public string VToken { get; set; }
    }
   
}
