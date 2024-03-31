namespace OpenIddictServerlessDemo;

public class LocalEntryPoint
{
  public static void Main(string[] args)
  {
    CreateHostBuilder(args).Build().Run();
  }

  public static IHostBuilder CreateHostBuilder(string[] args) =>
    Host.CreateDefaultBuilder(args)
      .ConfigureWebHostDefaults(webBuilder =>
      {
        webBuilder
          .ConfigureAppConfiguration(builder =>
          {
            builder.AddSystemsManager("/OpenIddictServerlessDemo/Certificates");
          })
          .UseStartup<Startup>();
      });
}
