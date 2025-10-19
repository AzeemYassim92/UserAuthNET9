namespace UserAuth.Entities
{
    public class RefreshToken
    {
        public Guid Id {get; set;}
        public Guid UserId {get; set;}
        public string Token { get; set; } = ""; 
        public DateTime CreatedAtUtc {get; set;}
        public DateTime ExpiresAtUtc {get; set;}
        public DateTime? RevokedAtUtc {get; set;}
        public string? CreatedByIp {get; set;}
        public string? RevokedByIp  {get; set;}

        public bool IsActive => RevokedAtUtc == null && DateTime.UtcNow < ExpiresAtUtc;
        public AppUser User { get; set; } = null; 
     
    }
}
