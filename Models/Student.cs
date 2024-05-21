using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;

namespace Final8Net.Models
{
    public class Student
    {
        [Key]
        public int id { get; set; }

        public required string Firstname { get; set; }

        public required string Lastname { get; set; }

        //public DateTime date_of_birth { get; set; }

        //public string gender { get; set; }

        public required string Email { get; set; }

        //public string phone_number { get; set; }

        //public string nationality { get; set; }

        //// public DateTime? registration_date { get; set; }

        //public string faculty { get; set; }
        public required string Password { get; set; }
        //public string StatusCode { get; internal set; }
    }
}
