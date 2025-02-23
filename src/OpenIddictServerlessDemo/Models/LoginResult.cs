using Microsoft.AspNetCore.Identity;

namespace OpenIddictServerlessDemo.Models;

public class LoginResult(SignInResult signInResult)
{
  public bool Succeeded { get; set; } = signInResult.Succeeded;
  public bool IsLockedOut { get; set; } = signInResult.IsLockedOut;
  public bool IsNotAllowed { get; set; } = signInResult.IsNotAllowed;
  public bool RequiresTwoFactor { get; set; } = signInResult.RequiresTwoFactor;
}
