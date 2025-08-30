using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using SaasIdentityAgent.Services;
using SaasIdentityAgent.Configuration;
using SaasIdentityAgent.Models;

namespace SaasIdentityAgent;

public class Program
{
    public static async Task Main(string[] args)
    {
        // Configure Serilog
        Log.Logger = new LoggerConfiguration()
            .WriteTo.File("logs/agent-.txt", rollingInterval: RollingInterval.Day)
            .WriteTo.EventLog("SaaS Identity Agent", manageEventSource: true)
            .CreateLogger();

        try
        {
            Log.Information("Starting SaaS Identity Agent");
            
            var host = CreateHostBuilder(args).Build();
            
            // Install/Uninstall service based on command line arguments
            if (args.Length > 0)
            {
                switch (args[0].ToLower())
                {
                    case "install":
                        await ServiceInstaller.InstallAsync();
                        return;
                    case "uninstall":
                        await ServiceInstaller.UninstallAsync();
                        return;
                    case "start":
                        await ServiceInstaller.StartAsync();
                        return;
                    case "stop":
                        await ServiceInstaller.StopAsync();
                        return;
                }
            }
            
            await host.RunAsync();
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Application terminated unexpectedly");
        }
        finally
        {
            Log.CloseAndFlush();
        }
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .UseWindowsService(options =>
            {
                options.ServiceName = "SaasIdentityAgent";
            })
            .UseSerilog()
            .ConfigureServices((hostContext, services) =>
            {
                // Configuration
                services.Configure<AgentConfiguration>(hostContext.Configuration.GetSection("Agent"));
                services.Configure<BackendConfiguration>(hostContext.Configuration.GetSection("Backend"));
                services.Configure<ActiveDirectoryConfiguration>(hostContext.Configuration.GetSection("ActiveDirectory"));
                
                // HTTP Client
                services.AddHttpClient<IBackendApiService, BackendApiService>(client =>
                {
                    var backendConfig = hostContext.Configuration.GetSection("Backend").Get<BackendConfiguration>();
                    client.BaseAddress = new Uri(backendConfig?.BaseUrl ?? "https://localhost:8000");
                    client.Timeout = TimeSpan.FromSeconds(30);
                });
                
                // Services
                services.AddSingleton<IActiveDirectoryService, ActiveDirectoryService>();
                services.AddSingleton<IBackendApiService, BackendApiService>();
                services.AddSingleton<IConfigurationService, ConfigurationService>();
                services.AddSingleton<ICredentialService, CredentialService>();
                
                // Background Services
                services.AddHostedService<HeartbeatService>();
                services.AddHostedService<SynchronizationService>();
                services.AddHostedService<CommandProcessorService>();
            });
}