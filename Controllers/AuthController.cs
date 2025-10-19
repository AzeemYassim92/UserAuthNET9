using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options; 
using Microsoft.AspNetCore.Mvc;
using UserAuth.DTO;
using UserAuth.Entities;
using UserAuth.Helpers;
using UserAuth.Services;
using Microsoft.EntityFrameworkCore;
using UserAuth.Data;
using System.Net;


namespace UserAuth.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<AppUser> _users;
        private readonly TokenService _tokens;
        private readonly IOptions<JwtOptions> _jwt;
        private readonly SignInManager<AppUser> _signIn;
        private readonly IEmailService _email;
        private readonly AppDbContext _db;

        public AuthController(UserManager<AppUser> users, TokenService tokens, IOptions<JwtOptions> jwt, SignInManager<AppUser> signIn, IEmailService email, AppDbContext db)
        {
            _users = users;
            _signIn = signIn;
            _tokens = tokens;
            _jwt = jwt;
            _email = email;
            _db = db;
        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterRequest req)
        {
            var existing = await _users.FindByEmailAsync(req.Email);
            if (existing is not null)
                return Conflict(new { message = "Email already registered" });
            var user = new AppUser
            {
                Id = Guid.NewGuid(),
                Email = req.Email,
                UserName = req.Email
            };

            var result = await _users.CreateAsync(user, req.Password);
            if (!result.Succeeded)
                return BadRequest(result.Errors.Select(e => e.Description));

            //Send email confirmation link (stubbed via Email Service) 
            var emailToken = await _users.GenerateEmailConfirmationTokenAsync(user);
            var emailLink = $"https://localhost:7132/api/Auth/confirm?userId={user.Id}&code={Uri.EscapeDataString(emailToken)}";
            await _email.SendAsync(user.Email!, "Confirm your email", emailLink);

            //Auto-login on register
            var claims = BuildClaims(user);
            var access = _tokens.CreateAccessToken(claims);
            var ttl = _jwt.Value.AccessTokenMinutes * 60;

            //Create and Persist refresh token 
            var refreshRaw = _tokens.CreateRefreshToken();
            _db.RefreshTokens.Add(new RefreshToken
            {
                Id = Guid.NewGuid(),
                UserId = user.Id,
                Token = refreshRaw,
                CreatedAtUtc = DateTime.UtcNow,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(_jwt.Value.RefreshTokenDays),
                CreatedByIp = HttpContext.Connection.RemoteIpAddress?.ToString()
            });
            await _db.SaveChangesAsync();

            return Ok(new AuthResponse { AccessToken = access, ExpiresInSeconds = ttl, RefreshToken = refreshRaw });
        }
        //nexty
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginRequest req)
        {
            var user = await _users.FindByEmailAsync(req.Email);
            if (user is null) return Unauthorized();

            var ok = await _users.CheckPasswordAsync(user, req.Password);
            if (!ok) return Unauthorized();

            var claims = BuildClaims(user);
            var access = _tokens.CreateAccessToken(claims);
            var ttl = _jwt.Value.AccessTokenMinutes * 60;
            var refreshRaw = _tokens.CreateRefreshToken();
            var refresh = new RefreshToken
            {
                Id = Guid.NewGuid(),
                UserId = user.Id,
                Token = refreshRaw,
                CreatedAtUtc = DateTime.UtcNow,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(_jwt.Value.RefreshTokenDays),
                CreatedByIp = HttpContext.Connection.RemoteIpAddress?.ToString()
            };
            _db.RefreshTokens.Add(refresh);
            await _db.SaveChangesAsync();
            return Ok(new AuthResponse { AccessToken = access, ExpiresInSeconds = ttl, RefreshToken = refreshRaw });
        }

        //new 
        [HttpPost("refresh")]
        [AllowAnonymous]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest req)
        {
            var token = await _db.RefreshTokens
                .Include(r => r.User)
                .FirstOrDefaultAsync(r => r.Token == req.RefreshToken);

            if (token is null || !token.IsActive) return Unauthorized();

            //Rotate refresh token 
            token.RevokedAtUtc = DateTime.UtcNow;
            token.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString();

            var newRaw = _tokens.CreateRefreshToken();
            _db.RefreshTokens.Add(new RefreshToken
            {
                Id = Guid.NewGuid(),
                UserId = token.UserId,
                Token = newRaw,
                CreatedAtUtc = DateTime.UtcNow,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(_jwt.Value.RefreshTokenDays),
                CreatedByIp = HttpContext.Connection.RemoteIpAddress?.ToString()
            });
            var claims = BuildClaims(token.User);
            var access = _tokens.CreateAccessToken(claims);
            var ttl = _jwt.Value.AccessTokenMinutes * 60;

            await _db.SaveChangesAsync(); 
            return Ok(new AuthResponse { AccessToken = access, ExpiresInSeconds = ttl, RefreshToken = newRaw });
        }

        //next to do is logout
        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] RefreshRequest req)
        {
            var token = await _db.RefreshTokens.FirstOrDefaultAsync(r => r.Token == req.RefreshToken);
            if (token is null) return Ok(); //idempotent

            token.RevokedAtUtc = DateTime.UtcNow;
            token.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString();
            await _db.SaveChangesAsync();
            return Ok(); 
        }

        [HttpPost("send-confirmation")]
        [Authorize]
        public async Task<IActionResult> SendConfirmation()
        {
            var user = await _users.GetUserAsync(User);
            if (user is null) return Unauthorized();

            var code = await _users.GenerateEmailConfirmationTokenAsync(user);
            var link = $"https://localhost:7132/api/Auth/confirm?userId={user.Id}&code={Uri.EscapeDataString(code)}";
            await _email.SendAsync(user.Email!, "Confirm your email", link);

            //returning link for dev
            return Ok(new { message = "Confirmation sent.", link }); 
        }
        [HttpGet("confirm")]
        [AllowAnonymous]
        public async Task<IActionResult> Confirm([FromQuery] Guid userId, [FromQuery]string code)
        {
            code = WebUtility.UrlDecode(code); 
            var user = await _users.FindByIdAsync(userId.ToString());
            if (user is null) return BadRequest("Invalid user.");

            var result = await _users.ConfirmEmailAsync(user, code);
            return result.Succeeded
                ? Ok(new { message = "Email confirmed." })
                : BadRequest(result.Errors.Select(e => e.Description)); 
        }

        public class ForgotPasswordRequest { public string Email { get; set; } = ""; }
        public class ResetPasswordRequest { public string Email { get; set; } = ""; public string Token { get; set; } = ""; public string NewPassword { get; set; } = ""; }

        [HttpPost("forget-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest req)
        {
            var user = await _users.FindByEmailAsync(req.Email);
            if (user is null) return Ok(); //avoid user enumeration 

            var code = await _users.GeneratePasswordResetTokenAsync(user);
            var link = $"https://localhost:7132/reset?email={Uri.EscapeDataString(req.Email)}&code={Uri.EscapeDataString(code)}";
            await _email.SendAsync(req.Email, "Reset your password", link);

            return Ok(new { message = "If that account exists, a reset link was sent.", link });

        }
        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest req)
        {
            var user = await _users.FindByEmailAsync(req.Email);
            if (user is null) return BadRequest("Invalid user.");

            var decoded = System.Net.WebUtility.UrlDecode(req.Token); 
            var result = await _users.ResetPasswordAsync(user, decoded, req.NewPassword);
            return result.Succeeded
                ? Ok(new { message = "Password reset successful" })
                : BadRequest(result.Errors.Select(e => e.Description)); 
        }

        [HttpGet("me")]
            [Authorize]
            public async Task<ActionResult<MeResponse>> Me()
            {
                var user = await _users.GetUserAsync(User);
                if (user is null) return Unauthorized();

                return new MeResponse {
                    Id = user.Id.ToString(),
                    Email = user.Email ?? "",
                    UserName = user.UserName
                }; 
            }

            private static IEnumerable<Claim> BuildClaims(AppUser user) => new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.UserName ?? user.Email ?? string.Empty),
                new Claim(ClaimTypes.Email, user.Email ?? string.Empty)
            };



        }
    
}
