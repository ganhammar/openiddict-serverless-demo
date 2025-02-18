using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Amazon.DynamoDBv2;
using AspNetCore.Identity.AmazonDynamoDB;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.AmazonDynamoDB;
using OpenIddict.Server.AspNetCore;
using OpenIddictServerlessDemo.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddSystemsManager("/OpenIddictServerlessDemo/Certificates");

var services = builder.Services;
var configuration = builder.Configuration;
var environment = builder.Environment;

services.AddAWSLambdaHosting(LambdaEventSource.HttpApi);
services
  .AddDefaultAWSOptions(configuration.GetAWSOptions())
  .AddSingleton<IAmazonDynamoDB>(new AmazonDynamoDBClient());

services
  .AddDataProtection()
  .PersistKeysToAWSSystemsManager("/OpenIddictServerlessDemo/DataProtection");

var getCertificateParts = (string cert) =>
{
  var signingCertificateParts = cert.Split("-----\n-----");

  var first = $"{signingCertificateParts[0]}-----";
  var second = $"-----{signingCertificateParts[1]}";

  return new
  {
    Cert = (first.Contains("BEGIN CERTIFICATE") ? first : second).AsMemory(),
    Key = (first.Contains("BEGIN CERTIFICATE") ? second : first).AsMemory()
  };
};

services
  .AddIdentity<DynamoDbUser, DynamoDbRole>()
  .AddDefaultTokenProviders()
  .AddDynamoDbStores()
  .SetDefaultTableName("openiddict-serverless-demo.identity");

services
  .AddOpenIddict()
  .AddCore(builder =>
  {
    builder
      .UseDynamoDb()
      .SetDefaultTableName("openiddict-serverless-demo.openiddict");
  })
  .AddServer(builder =>
  {
    builder.SetTokenEndpointUris("/connect/token");
    builder.SetAuthorizationEndpointUris("/connect/authorize");

    builder.AllowClientCredentialsFlow();
    builder.AllowAuthorizationCodeFlow();

    var aspNetCoreBuilder = builder
      .UseAspNetCore()
      .EnableTokenEndpointPassthrough();

    if (environment.IsDevelopment())
    {
      builder.AddEphemeralEncryptionKey();
      builder.AddEphemeralSigningKey();
      aspNetCoreBuilder.DisableTransportSecurityRequirement();
    }
    else
    {
      var signingCertificate = configuration.GetValue<string>("SigningCertificate");
      var encryptionCertificate = configuration.GetValue<string>("EncryptionCertificate");

      if (string.IsNullOrEmpty(signingCertificate) || string.IsNullOrEmpty(encryptionCertificate))
      {
        throw new InvalidOperationException("SigningCertificate and EncryptionCertificate must be set in the configuration.");
      }

      var signingCertificateParts = getCertificateParts(signingCertificate);
      var encryptionCertificateParts = getCertificateParts(encryptionCertificate);

      builder
        .AddSigningCertificate(X509Certificate2.CreateFromPem(signingCertificateParts.Cert.Span, signingCertificateParts.Key.Span));
      builder
        .AddEncryptionCertificate(X509Certificate2.CreateFromPem(encryptionCertificateParts.Cert.Span, encryptionCertificateParts.Key.Span));
    }
  });

var app = builder.Build();

app.MapPost("/api/connect/token", async (
  HttpContext httpContext,
  IOpenIddictApplicationManager applicationManager,
  IOpenIddictScopeManager scopeManager) =>
{
  var openIddictRequest = httpContext.GetOpenIddictServerRequest()!;
  var application = await applicationManager.FindByClientIdAsync(openIddictRequest.ClientId!);

  if (application == default)
  {
    return Results.Challenge(
      authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
      properties: new AuthenticationProperties(new Dictionary<string, string?>
      {
        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The specified hardcoded identity is invalid."
      }));
  }

  var identity = new ClaimsIdentity(
    TokenValidationParameters.DefaultAuthenticationType,
    Claims.Name, Claims.Role);

  identity.SetClaim(Claims.Subject, (await applicationManager.GetClientIdAsync(application))!);

  var principal = new ClaimsPrincipal(identity);
  principal.SetScopes(openIddictRequest.GetScopes());
  principal.SetResources(await scopeManager.ListResourcesAsync(principal.GetScopes()).ToListAsync());

  return Results.SignIn(principal, new(), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
});

app.MapPost("/api/connect/authorize", async (
  HttpContext httpContext,
  UserManager<DynamoDbUser> userManager,
  SignInManager<DynamoDbUser> signInManager,
  IOpenIddictScopeManager scopeManager) =>
{
  var openIddictRequest = httpContext.GetOpenIddictServerRequest();

  if (httpContext.User?.Identity?.IsAuthenticated != true)
  {
    return Results.Challenge();
  }

  var user = await userManager.GetUserAsync(httpContext.User);
  var principal = await signInManager.CreateUserPrincipalAsync(user!);

  var scopes = openIddictRequest!.GetScopes();
  principal.SetScopes(scopes);
  principal.SetResources(await scopeManager.ListResourcesAsync(scopes).ToListAsync());

  foreach (var claim in principal.Claims)
  {
    claim.SetDestinations(GetDestinations(claim, principal));
  }

  return Results.SignIn(principal, new(), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
});

static IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
{
  switch (claim.Type)
  {
    case Claims.Name:
      yield return Destinations.AccessToken;

      if (principal.HasScope(Scopes.Profile))
        yield return Destinations.IdentityToken;

      yield break;

    case Claims.Email:
      yield return Destinations.AccessToken;

      if (principal.HasScope(Scopes.Email))
        yield return Destinations.IdentityToken;

      yield break;

    case Claims.Role:
      yield return Destinations.AccessToken;

      if (principal.HasScope(Scopes.Roles))
        yield return Destinations.IdentityToken;

      yield break;

    // Never include the security stamp in the access and identity tokens, as it's a secret value.
    case "AspNet.Identity.SecurityStamp": yield break;

    default:
      yield return Destinations.AccessToken;
      yield break;
  }
}

app.MapPost("/api/user/login", [Consumes("application/json")] async (
  Login? login,
  HttpContext httpContext,
  UserManager<DynamoDbUser> userManager,
  SignInManager<DynamoDbUser> signInManager) =>
{
  if (string.IsNullOrEmpty(login?.Email) || string.IsNullOrEmpty(login?.Password))
  {
    return Results.BadRequest();
  }

  var user = await userManager.FindByEmailAsync(login.Email);
  if (user == default)
  {
    return Results.BadRequest();
  }

  return Results.Ok(new LoginResult(
    await signInManager.PasswordSignInAsync(
      user.UserName!, login.Password, false, false)));
});

app.MapGet("/api/user/current", async(
  HttpContext httpContext,
  UserManager<DynamoDbUser> userManager
) =>
{
  if (httpContext!.User?.Identity?.IsAuthenticated != true)
  {
    return Results.NotFound();
  }

  var user = await userManager.GetUserAsync(httpContext!.User);
  return Results.Ok(user);
});

// Setup: Only for demo purpose, should not be run during startup in production, move to setup script
OpenIddictDynamoDbSetup.EnsureInitialized(app.Services);
AspNetCoreIdentityDynamoDbSetup.EnsureInitialized(app.Services);
using (var scope = app.Services.CreateScope())
{
  CreateDemoClient(scope.ServiceProvider).GetAwaiter().GetResult();
  CreateDemoUser(scope.ServiceProvider).GetAwaiter().GetResult();
}

static async Task CreateDemoClient(IServiceProvider provider)
{
  var manager = provider.GetRequiredService<IOpenIddictApplicationManager>();
  var clientId = "openiddict-serverless-demo";

  var exists = await manager.FindByClientIdAsync(clientId);
  if (exists != null)
  {
    return;
  }

  await manager.CreateAsync(new()
  {
    ClientId = clientId,
    ClientSecret = "388D45FA-B36B-4988-BA59-B187D329C207",
    DisplayName = "Demo client application",
    Permissions =
    {
      Permissions.Endpoints.Token,
      Permissions.GrantTypes.ClientCredentials
    }
  });
}

static async Task CreateDemoUser(IServiceProvider provider)
{
  var manager = provider.GetRequiredService<UserManager<DynamoDbUser>>();
  var user = new DynamoDbUser
  {
    UserName = "Alice",
    Email = "alice@wonderland.com"
  };

  await manager.CreateAsync(user, "Pass@word1");
}
// End of setup

app.Run();
