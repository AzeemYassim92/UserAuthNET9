namespace UserAuth.Helpers
{
    public class SeedAdminOptions
    {
        public string Email { get; set; } = ""; 
        public string Password { get; set; } = "";
        public bool ConfirmEmail { get; set; } = true;
        public string[] Roles { get; set; } = new[] { RoleNames.Admin }; 
    }
}
