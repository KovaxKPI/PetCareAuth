using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using PetCareAuth.Identity;
using PetCareAuth.Services;

namespace PetCareAuth.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthorizationController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, ITokenService tokenService) : ControllerBase
{
    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest request)
    {
        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email
        };

        var result = await userManager.CreateAsync(
            user,
            request.Password);

        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        return Ok(new
        {
            user.Id,
            user.Email
        });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequest loginRequest)
    {
        var user = await userManager.FindByEmailAsync(loginRequest.Email);
        
        if (user is null)
            return BadRequest("Invalid username or password");

        var passwordValid = await userManager.CheckPasswordAsync(
            user,
            loginRequest.Password);

        if (!passwordValid)
            return BadRequest("Invalid username or password");

        var roles = await userManager.GetRolesAsync(user);

        var token = tokenService.GenerateToken(user, roles);

        return Ok(new
        {
            accessToken = token
        });
    }
    
    [HttpGet("google")]
    public IActionResult GoogleLogin()
    {
        var properties =
            signInManager.ConfigureExternalAuthenticationProperties(
                GoogleDefaults.AuthenticationScheme,
                Url.Action(nameof(GoogleCallback))!);

        return Challenge(
            properties,
            GoogleDefaults.AuthenticationScheme);
    }
    
    [HttpGet("google-callback")]
    public async Task<IActionResult> GoogleCallback()
    {
        var info = await signInManager.GetExternalLoginInfoAsync();

        if (info is null)
            return BadRequest("Error loading external login information");

        var result = await signInManager.ExternalLoginSignInAsync(
            info.LoginProvider,
            info.ProviderKey,
            isPersistent: false,
            bypassTwoFactor: true);

        if (result.Succeeded)
        {
            var user = await userManager.FindByLoginAsync(
                info.LoginProvider,
                info.ProviderKey);

            if (user is null)
                return BadRequest();

            var roles = await userManager.GetRolesAsync(user);

            var token = tokenService.GenerateToken(user, roles);

            return Ok(new
            {
                accessToken = token
            });
        }

        if (result.IsLockedOut)
            return BadRequest("User is locked out");

        var email = info.Principal.FindFirstValue(
            ClaimTypes.Email);

        if (string.IsNullOrWhiteSpace(email))
            return BadRequest("Google account has no email");

        var userByEmail = await userManager.FindByEmailAsync(email);

        if (userByEmail is not null)
        {
            var addLoginResult = await userManager.AddLoginAsync(
                userByEmail,
                info);

            if (!addLoginResult.Succeeded)
                return BadRequest(addLoginResult.Errors);

            var roles = await userManager.GetRolesAsync(userByEmail);

            var token = tokenService.GenerateToken(
                userByEmail,
                roles);

            return Ok(new
            {
                accessToken = token
            });
        }

        var newUser = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true
        };

        var createResult = await userManager.CreateAsync(newUser);

        if (!createResult.Succeeded)
            return BadRequest(createResult.Errors);

        var loginResult = await userManager.AddLoginAsync(
            newUser,
            info);

        if (!loginResult.Succeeded)
            return BadRequest(loginResult.Errors);

        var userRoles = await userManager.GetRolesAsync(newUser);

        var jwt = tokenService.GenerateToken(
            newUser,
            userRoles);

        return Ok(new
        {
            accessToken = jwt
        });
    }
}