using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using UserAuth.Entities; 

namespace UserAuth.Data
{

    public class AppDbContext : IdentityDbContext<AppUser, IdentityRole<Guid>, Guid>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
        public DbSet<RefreshToken> RefreshTokens=> Set<RefreshToken>();


        protected override void OnModelCreating(ModelBuilder b)
        {
            base.OnModelCreating(b);

            //Optional 
            b.Entity<AppUser>().ToTable("Users");
            b.Entity<IdentityRole<Guid>>().ToTable("Roles");
            b.Entity<IdentityUserRole<Guid>>().ToTable("UserRoles");
            b.Entity<IdentityUserClaim<Guid>>().ToTable("UserClaims");
            b.Entity<IdentityUserLogin<Guid>>().ToTable("UserLogins");
            b.Entity<IdentityRoleClaim<Guid>>().ToTable("RoleClaims");
            b.Entity<IdentityUserToken<Guid>>().ToTable("UserTokens");

            b.Entity<RefreshToken>(e =>
            {
                e.ToTable("RefreshTokens");
                e.HasKey(x => x.Id);
                e.HasIndex(x => x.Token).IsUnique();
                e.HasOne(x => x.User)
                .WithMany()
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            });
        }
    }
}
