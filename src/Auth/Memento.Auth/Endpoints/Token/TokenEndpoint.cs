using FastEndpoints;
using Memento.Auth.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Memento.Auth.Endpoints.Token;

public sealed class TokenEndpoint(UserManager<IdentityUser> userManager, IOptions<JwtOptions> jwtOptions) : Endpoint<TokenRequest, TokenResponse>
{
    private readonly UserManager<IdentityUser> _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager), "User manager must not be null");
    private readonly JwtOptions _jwtOptions = jwtOptions.Value;

    public override void Configure()
    {
        Post("/api/token");
        AllowAnonymous();
    }

    public override async Task HandleAsync(TokenRequest request, CancellationToken token)
    {
        var user = await _userManager.FindByNameAsync(request.Username);

        if (user is null || !await _userManager.CheckPasswordAsync(user, request.Password))
        {
            await Send.UnauthorizedAsync(cancellation: token);
            return;
        }

        var roles = await _userManager.GetRolesAsync(user);

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.SigningKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        List<Claim> claims =
        [
            new(JwtRegisteredClaimNames.Sub, user.Id),
            ..roles.Select(x => new Claim("role", x)),
        ];

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = _jwtOptions.Issuer,
            Audience = _jwtOptions.Audience,
            Expires = DateTime.UtcNow.AddMinutes(_jwtOptions.ExpirationInMinutes),
            SigningCredentials = credentials,
            Subject = new ClaimsIdentity(claims),
        };

        var handler = new JsonWebTokenHandler();
        string accessToken = handler.CreateToken(tokenDescriptor);

        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            //Secure = true, // return when finished with HTTPS
            Expires = DateTime.UtcNow.AddMinutes(_jwtOptions.ExpirationInMinutes),
        };

        HttpContext.Response.Cookies.Append("AuthToken", accessToken, cookieOptions);

        await Send.OkAsync(new TokenResponse { AccessToken = accessToken }, cancellation: token);
    }
}
