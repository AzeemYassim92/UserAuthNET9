namespace UserAuth.DTO
{
    public class AuthResponse
    {
        public string AccessToken { get; set; } = "";
        public int ExpiresInSeconds { get; set; }
        public string RefreshToken { get; set; } = ""; 
    }
}
