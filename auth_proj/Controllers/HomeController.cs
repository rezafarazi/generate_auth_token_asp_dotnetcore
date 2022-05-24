using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using auth_proj.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

namespace auth_proj.Controllers;

[Authorize]
public class HomeController : Controller
{

    [AllowAnonymous]
    [Route("")]
    public async Task<IActionResult> Index()
    {
        return View("Login");
    }
    
    [AllowAnonymous]
    [HttpPost]
    [Route("Login")]
    public async Task<IActionResult> Login(string username,string password)
    {
        List<Claim> tokens = new List<Claim>();
        tokens.Add(new Claim("username",username));
        tokens.Add(new Claim("password",password));

        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("JWTAuthenticationHIGHsecuredPasswordVVVp1OH7Xzyr"));
        
        JwtSecurityToken token = new JwtSecurityToken(
            issuer:"http://google.com",
            audience:"http://google.com",
            expires:DateTime.Now.AddHours(3),
            claims:tokens,
            signingCredentials:new SigningCredentials(
                authSigningKey,
                SecurityAlgorithms.HmacSha256Signature)
        );

        return Ok(new{
            token = new JwtSecurityTokenHandler().WriteToken(token)
        });

    }
    
    [Route("Dashboard")]
    public async Task<IActionResult> Dashboard()
    {
        return Content("Dashboard");
    }
    
}