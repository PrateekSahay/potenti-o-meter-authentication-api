using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace UserLoginAPI.Models
{
    public class UserLoginAPIContext : DbContext
    {
        public UserLoginAPIContext (DbContextOptions<UserLoginAPIContext> options)
            : base(options)
        {
        }

        //This function checks if the email id already exists or not
        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.Entity<User>(entity => entity.HasIndex(e => e.Email).IsUnique());
        }

        public DbSet<UserLoginAPI.Models.User> User { get; set; }
    }
}
