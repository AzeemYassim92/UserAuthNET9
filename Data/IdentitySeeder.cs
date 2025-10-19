using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Writers;
using UserAuth.Entities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using UserAuth.Helpers;

namespace UserAuth.Data
{
    public class IdentitySeeder
    {
        private readonly RoleManager<IdentityRole<Guid>> _roles;
        private readonly UserManager<AppUser> _users;
        private readonly IOptions<SeedAdminOptions> _opts;
        private readonly ILogger<IdentitySeeder> _log; 

        public IdentitySeeder(RoleManager<IdentityRole<Guid>> roles, UserManager<AppUser> users, 
            IOptions<SeedAdminOptions> opts, ILogger<IdentitySeeder> log)
        {
            _roles = roles; _users = users; _opts = opts; _log = log;
        }

        public async Task SeedAsync()
        {
            //roles 
            foreach(var role in new[] {RoleNames.Admin, RoleNames.Seller, RoleNames.Buyer})
                if (!await _roles.RoleExistsAsync(role))
                    await _roles.CreateAsync(new IdentityRole<Guid>(role));

            //admin user
            var email = _opts.Value.Email;
            var pwd = _opts.Value.Password; 
            if(string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(pwd))
            { _log.LogInformation("SeedAdminOptions missing; skipping admin seed"); return; }

            var user = await _users.FindByEmailAsync(email); 
            if(user is null)
            {
                user = new AppUser { Id = Guid.NewGuid(), Email = email, UserName = email, EmailConfirmed = _opts.Value.ConfirmEmail };
                var create = await _users.CreateAsync(user, pwd); 
                if(!create.Succeeded) { _log.LogError("Admin create failed: {e}", string.Join(", ", create.Errors.Select(x => x.Description))); return; }

                if(_opts.Value.ConfirmEmail && !user.EmailConfirmed)
                {
                    var token = await _users.GenerateEmailConfirmationTokenAsync(user);
                    await _users.ConfirmEmailAsync(user, token); 
                }

                //Ensure Roles
                var desired = _opts.Value.Roles?.Length > 0 ? _opts.Value.Roles : new[] { RoleNames.Admin };
                foreach (var role in desired)
                    if (!await _users.IsInRoleAsync(user, role))
                        await _users.AddToRoleAsync(user, role); 

            }
        }
    }
}
