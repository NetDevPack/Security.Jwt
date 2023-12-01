using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Identity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Interfaces;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace Identity.Controllers
{
    [ApiController]
    [Route("api/identity")]
    public class AuthController : ControllerBase
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IJwtService _jwtService;

        public AuthController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, IJwtService jwksService)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _jwtService = jwksService;
        }

        [HttpPost("new-account")]
        public async Task<ActionResult> Register(UserRegister newUser)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var user = new IdentityUser
            {
                UserName = newUser.Email,
                Email = newUser.Email,
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, newUser.Password);

            if (result.Succeeded)
            {
                var at = await GenerateAccessToken(user.Email);
                var rt = await GenerateRefreshToken(user.Email);
                return Ok(new UserLoginResponse(at, rt));
            }

            return BadRequest(result.Errors);
        }

        [HttpPost("signin")]
        public async Task<ActionResult> Login(UserLogin user)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var result = await _signInManager.PasswordSignInAsync(user.Email, user.Password,
                false, true);

            if (result.IsLockedOut)
                return BadRequest("Account blocked");

            if (!result.Succeeded)
                return BadRequest("Invalid username or password");

            var at = await GenerateAccessToken(user.Email);
            var rt = await GenerateRefreshToken(user.Email);
            return Ok(new UserLoginResponse(at, rt));
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult> RefreshToken(Token token)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var handler = new JsonWebTokenHandler();

            var result = handler.ValidateToken(token.RefreshToken, new TokenValidationParameters()
            {
                ValidIssuer = "https://www.devstore.academy", // <- Your website
                ValidAudience = "NetDevPack.Security.Jwt.AspNet",
                RequireSignedTokens = false,
                IssuerSigningKey = await _jwtService.GetCurrentSecurityKey(),
            });

            if (!result.IsValid)
                return BadRequest("Expired token");

            var user = await _userManager.FindByEmailAsync(result.Claims[JwtRegisteredClaimNames.Email].ToString());
            var claims = await _userManager.GetClaimsAsync(user);

            if (!claims.Any(c => c.Type == "LastRefreshToken" && c.Value == result.Claims[JwtRegisteredClaimNames.Jti].ToString()))
                return BadRequest("Expired token");

            if (user.LockoutEnabled)
                if (user.LockoutEnd < DateTime.Now)
                    return BadRequest("User blocked");

            if (claims.Any(c => c.Type == "TenhoQueRelogar" && c.Value == "true"))
                return BadRequest("User must login again");


            var at = await GenerateAccessToken(result.Claims[JwtRegisteredClaimNames.Email].ToString());
            var rt = await GenerateRefreshToken(result.Claims[JwtRegisteredClaimNames.Email].ToString());
            return Ok(new UserLoginResponse(at, rt));
        }


        private async Task<string> GenerateAccessToken(string? email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            var userRoles = await _userManager.GetRolesAsync(user);
            var identityClaims = new ClaimsIdentity();
            identityClaims.AddClaims(await _userManager.GetClaimsAsync(user));
            identityClaims.AddClaims(userRoles.Select(s => new Claim("role", s)));

            identityClaims.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
            identityClaims.AddClaim(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            identityClaims.AddClaim(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

            var handler = new JwtSecurityTokenHandler();
            var key = await _jwtService.GetCurrentSigningCredentials();
            var securityToken = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "https://www.devstore.academy", // <- Your website
                Audience = "NetDevPack.Security.Jwt.AspNet",
                SigningCredentials = key,
                Subject = identityClaims,
                NotBefore = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMinutes(60),
                IssuedAt = DateTime.UtcNow,
                TokenType = "at+jwt"
            });

            var encodedJwt = handler.WriteToken(securityToken);
            return encodedJwt;
        }


        private async Task<string> GenerateRefreshToken(string? email)
        {
            var jti = Guid.NewGuid().ToString();
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Email, email),
                new Claim(JwtRegisteredClaimNames.Jti, jti)
            };

            // Necessario converver para IdentityClaims
            var identityClaims = new ClaimsIdentity();
            identityClaims.AddClaims(claims);

            var handler = new JwtSecurityTokenHandler();

            var securityToken = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "https://www.devstore.academy", // <- Your website
                Audience = "NetDevPack.Security.Jwt.AspNet",
                SigningCredentials = await _jwtService.GetCurrentSigningCredentials(),
                Subject = identityClaims,
                NotBefore = DateTime.Now,
                Expires = DateTime.Now.AddDays(30),
                TokenType = "rt+jwt"
            });
            await UpdateLastGeneratedClaim(email, jti);
            var encodedJwt = handler.WriteToken(securityToken);
            return encodedJwt;
        }

        private async Task UpdateLastGeneratedClaim(string? email, string jti)
        {
            var user = await _userManager.FindByEmailAsync(email);
            var claims = await _userManager.GetClaimsAsync(user);
            var newLastRtClaim = new Claim("LastRefreshToken", jti);

            var claimLastRt = claims.FirstOrDefault(f => f.Type == "LastRefreshToken");
            if (claimLastRt != null)
                await _userManager.ReplaceClaimAsync(user, claimLastRt, newLastRtClaim);
            else
                await _userManager.AddClaimAsync(user, newLastRtClaim);

        }
    }
}
