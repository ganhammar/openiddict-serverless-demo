using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.AspNetCoreServer;
using Amazon.Lambda.Core;
using Amazon.Lambda.Serialization.SystemTextJson;
using AWS.Lambda.Powertools.Logging;
using AWS.Lambda.Powertools.Tracing;

namespace OpenIddictServerlessDemo;

public class LambdaEntryPoint : APIGatewayProxyFunction
{
  protected override void Init(IWebHostBuilder builder)
  {
    builder
      .ConfigureAppConfiguration(builder =>
      {
        builder.AddSystemsManager("/OpenIddictServerlessDemo/Certificates");
      })
      .UseStartup<Startup>();
  }

  protected override void Init(IHostBuilder builder) { }

  private Dictionary<string, string> _defaultDimensions = new()
  {
    {"Environment", Environment.GetEnvironmentVariable("ENVIRONMENT") ??  "Unknown"},
    {"Runtime",Environment.Version.ToString()}
  };

  [LambdaSerializer(typeof(DefaultLambdaJsonSerializer))]
  [Logging(CorrelationIdPath = CorrelationIdPaths.ApiGatewayRest, LogEvent = true)]
  [Tracing]
  public override Task<APIGatewayProxyResponse> FunctionHandlerAsync(
    APIGatewayProxyRequest request, ILambdaContext lambdaContext)
  {
    if (!_defaultDimensions.ContainsKey("Version"))
      _defaultDimensions.Add("Version", lambdaContext.FunctionVersion ?? "Unknown");

    return base.FunctionHandlerAsync(request, lambdaContext);
  }
}
