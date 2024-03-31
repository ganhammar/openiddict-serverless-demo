using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddictServerlessDemo.Controllers;

public class TokenController(
  IOpenIddictApplicationManager applicationManager,
  IOpenIddictScopeManager scopeManager) : Controller
{
  [HttpPost("/connect/token")]
  [Produces("application/json")]
  public async Task<IActionResult> Token()
  {
    var openIddictRequest = HttpContext.GetOpenIddictServerRequest()!;
    var application = await applicationManager.FindByClientIdAsync(openIddictRequest.ClientId!);

    if (application == default)
    {
      return BadRequest(new OpenIddictResponse
      {
        Error = Errors.InvalidClient,
        ErrorDescription = "The specified client identifier is invalid."
      });
    }

    var identity = new ClaimsIdentity(
        TokenValidationParameters.DefaultAuthenticationType,
        Claims.Name, Claims.Role);

    // Use the client_id as the subject identifier.
    identity.SetClaim(Claims.Subject, (await applicationManager.GetClientIdAsync(application))!);

    var principal = new ClaimsPrincipal(identity);
    principal.SetScopes(openIddictRequest.GetScopes());
    principal.SetResources(await scopeManager.ListResourcesAsync(principal.GetScopes()).ToListAsync());

    return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
  }
}
