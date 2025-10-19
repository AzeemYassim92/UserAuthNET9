using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using UserAuth.Entities;
using UserAuth.Helpers;
using Microsoft.AspNetCore.Identity;

[ApiController]
[Route("api/admin")]
[Authorize] // just authenticated
public class AdminController : ControllerBase
{
    [HttpGet("ping")]
    public async Task<IActionResult> Ping(
        [FromServices] UserManager<AppUser> users)
    {
        var me = await users.GetUserAsync(User);
        if (me is null) return Unauthorized();

        var isAdmin = await users.IsInRoleAsync(me, RoleNames.Admin);
        if (!isAdmin) return Forbid();     // <- 403 if not Admin

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var email = User.FindFirstValue(ClaimTypes.Email);
        return Ok(new { ok = true, role = "Admin", userId, email });
    }
}
