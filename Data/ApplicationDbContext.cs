using Final8Net.Models;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
namespace Final8Net.Data
{
    public class ApplicationDbContext : DbContext
    { 
        public ApplicationDbContext(DbContextOptions options) : base(options)
        {

        }
        //Table In MySQL Name
        public DbSet<Student> student { get; set; }
        public DbSet<UnVerified> unverified { get; set; }
        public DbSet<Course> Course { get; set; }
    }
}
