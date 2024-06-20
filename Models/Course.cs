using System.ComponentModel.DataAnnotations;

namespace Final8Net.Models
{
    public class Course
    {
        [Key]
        public int Id { get; set; }
        [Required]
        public string Title { get; set; }
        [Required]
        public string ImageUrl { get; set; }
        [Required]
        public string Url { get; set; }
    }
}
