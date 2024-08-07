using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Amazon.DynamoDBv2;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.AmazonDynamoDB;
using OpenIddict.Server.AspNetCore;
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
    builder.AllowClientCredentialsFlow();

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

app.MapPost("/connect/token", async (
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

// Setup: Only for demo purpose, should not be run during startup in production, move to setup script
OpenIddictDynamoDbSetup.EnsureInitialized(app.Services);
using (var scope = app.Services.CreateScope())
{
  CreateDemoClient(scope.ServiceProvider).GetAwaiter().GetResult();
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
// End of setup

app.Run();
