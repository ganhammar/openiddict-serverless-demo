using Microsoft.AspNetCore.Identity;

namespace OpenIddictServerlessDemo.Models;

public class LoginResult
{
  public LoginResult() { }

  public LoginResult(SignInResult signInResult)
  {
    Succeeded = signInResult.Succeeded;
    IsLockedOut = signInResult.IsLockedOut;
    IsNotAllowed = signInResult.IsNotAllowed;
    RequiresTwoFactor = signInResult.RequiresTwoFactor;
  }

  public bool Succeeded { get; set; }
  public bool IsLockedOut { get; set; }
  public bool IsNotAllowed { get; set; }
  public bool RequiresTwoFactor { get; set; }
}
