using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SpaTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        [Authorize]
        [HttpGet("me")]
        public IActionResult Get()
        {
            //get user name 
            var userName = User.FindFirst(ClaimTypes.Name)?.Value;
            // 實現身分驗證後的業務邏輯
            return Ok(new { name = userName });
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginModel loginModel)
        {
            //如果是合法用戶
            if (IsValidUser(loginModel))
            {
                //產生token
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes("this is my custom Secret key for authentication");
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                        new Claim(ClaimTypes.Name, loginModel.Username)
                    }),
                    Issuer = "your_issuer",
                    Audience = "your_audience",
                    Expires = DateTime.UtcNow.AddSeconds(30), //為了方便測試，30秒就過期
                    SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);
                return Ok(new { Token = tokenString });
            }
            return Unauthorized();
        }

        [Authorize]
        [HttpPost("logout")]
        public IActionResult Logout()
        {
            // 將當前用戶的 Token 過期時間設置為當前時間，即可強制登出
            var user = User.Identity.Name;
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            var token = new JwtSecurityToken(
                issuer: "your_issuer",
                audience: "your_audience",
                claims: claims,
                expires: DateTime.UtcNow,
                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes("this is my custom Secret key for authentication")), SecurityAlgorithms.HmacSha256Signature)
            );
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            return Ok(new { Token = tokenString });
        }

        //驗證用戶身分
        private bool IsValidUser(LoginModel loginModel)
        {
            //只有用戶名稱是test才成功登入
            return loginModel.Password == "super";
        }
    }

    /// <summary>
    /// 用戶登入帳號密碼
    /// </summary>
    public class LoginModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
