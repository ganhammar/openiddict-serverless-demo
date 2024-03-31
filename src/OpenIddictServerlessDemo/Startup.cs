using System.Security.Cryptography.X509Certificates;
using Amazon.DynamoDBv2;
using Amazon.XRay.Recorder.Handlers.AwsSdk;
using Microsoft.IdentityModel.Logging;
using OpenIddict.Abstractions;
using OpenIddict.AmazonDynamoDB;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddictServerlessDemo;

public class Startup(IConfiguration configuration, IHostEnvironment environment)
{
  public void ConfigureServices(IServiceCollection services)
  {
    AWSSDKHandler.RegisterXRayForAllServices();

    services
      .AddDefaultAWSOptions(configuration.GetAWSOptions())
      .AddSingleton<IAmazonDynamoDB>(_ => new AmazonDynamoDBClient());

    services.AddDataProtection()
      .PersistKeysToAWSSystemsManager("/OpenIddictServerlessDemo/DataProtection");

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
        builder
          .SetTokenEndpointUris("/connect/token")
          .SetIntrospectionEndpointUris("/connect/introspect")
          .SetCryptographyEndpointUris("/.well-known/jwks")
          .SetConfigurationEndpointUris("/.well-known/openid-configuration");

        builder.AllowClientCredentialsFlow();

        builder.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles);

        builder.SetAccessTokenLifetime(TimeSpan.FromMinutes(30));

        var aspNetCoreBuilder = builder
          .UseAspNetCore()
          .EnableStatusCodePagesIntegration()
          .EnableTokenEndpointPassthrough();

        var signingCertificate = configuration.GetValue<string>("SigningCertificate");
        var encryptionCertificate = configuration.GetValue<string>("EncryptionCertificate");

        if (string.IsNullOrEmpty(signingCertificate) || string.IsNullOrEmpty(encryptionCertificate))
        {
          throw new InvalidOperationException("SigningCertificate and EncryptionCertificate must be set in the configuration.");
        }

        builder
          .AddSigningCertificate(new X509Certificate2(Convert.FromBase64String(signingCertificate)))
          .AddEncryptionCertificate(new X509Certificate2(Convert.FromBase64String(encryptionCertificate)));

        if (environment.IsDevelopment())
        {
          aspNetCoreBuilder.DisableTransportSecurityRequirement();
        }
      });

    if (environment.IsDevelopment())
    {
      IdentityModelEventSource.ShowPII = true;
    }

    services.AddHttpContextAccessor();
    services.AddControllers();
  }

  public void Configure(IApplicationBuilder app)
  {
    OpenIddictDynamoDbSetup.EnsureInitialized(app.ApplicationServices);
    using (var scope = app.ApplicationServices.CreateScope())
    {
      CreateDemoClient(scope.ServiceProvider).GetAwaiter().GetResult();
    }

    app.UseXRay("openiddict-serverless-demo");
    app.UseRouting();
    app.UseAuthentication();
    app.UseAuthorization();
    app.UseEndpoints(options =>
    {
      options.MapControllers();
      options.MapDefaultControllerRoute();
    });
  }

  private static async Task CreateDemoClient(IServiceProvider provider)
  {
    var manager = provider.GetRequiredService<IOpenIddictApplicationManager>();
    var clientId = "openiddict-serverless-demo";

    var exists = await manager.FindByClientIdAsync(clientId);

    if (exists != null)
    {
      return;
    }

    var descriptor = new OpenIddictApplicationDescriptor
    {
      ClientId = clientId,
      ClientSecret = "388D45FA-B36B-4988-BA59-B187D329C207",
      DisplayName = "Demo client application",
      Permissions =
      {
        Permissions.Endpoints.Token,
        Permissions.GrantTypes.ClientCredentials
      }
    };

    await manager.CreateAsync(descriptor);
  }
}
