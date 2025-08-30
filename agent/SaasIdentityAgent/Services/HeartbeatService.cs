using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SaasIdentityAgent.Models;
using System.Diagnostics;
using System.Management;

namespace SaasIdentityAgent.Services;

public class HeartbeatService : BackgroundService
{
    private readonly ILogger<HeartbeatService> _logger;
    private readonly IServiceProvider _serviceProvider;
    private readonly AgentConfiguration _config;
    private readonly string _agentId;
    private readonly string _version;

    public HeartbeatService(
        ILogger<HeartbeatService> logger,
        IServiceProvider serviceProvider,
        IOptions<AgentConfiguration> config)
    {
        _logger = logger;
        _serviceProvider = serviceProvider;
        _config = config.Value;
        _agentId = _config.AgentId;
        _version = _config.Version;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Heartbeat service started");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await SendHeartbeatAsync();
                await Task.Delay(TimeSpan.FromSeconds(_config.HeartbeatIntervalSeconds), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Heartbeat service is stopping");
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in heartbeat service");
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken); // Wait before retry
            }
        }
    }

    private async Task SendHeartbeatAsync()
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var backendApi = scope.ServiceProvider.GetRequiredService<IBackendApiService>();
            var adService = scope.ServiceProvider.GetRequiredService<IActiveDirectoryService>();

            var systemInfo = await GetSystemInfoAsync();
            var adStatus = await adService.TestConnectionAsync();

            var heartbeatRequest = new HeartbeatRequest
            {
                AgentId = _agentId,
                TenantId = _config.TenantId,
                Timestamp = DateTime.UtcNow,
                Version = _version,
                SystemInfo = systemInfo,
                Status = adStatus ? "healthy" : "ad_connection_failed"
            };

            var response = await backendApi.SendHeartbeatAsync(heartbeatRequest);

            if (response != null)
            {
                _logger.LogDebug("Heartbeat sent successfully. Server time: {ServerTime}", response.ServerTime);
                
                // Process any pending sync requests
                if (response.PendingSync != null && response.PendingSync.RequiresSync)
                {
                    _logger.LogInformation("Sync requested by server. Type: {SyncType}", response.PendingSync.SyncType);
                    await TriggerSyncAsync(response.PendingSync.SyncType);
                }

                // Process any pending commands
                if (response.Commands != null && response.Commands.Any())
                {
                    _logger.LogInformation("Received {Count} commands from server", response.Commands.Count);
                    await ProcessCommandsAsync(response.Commands);
                }
            }
            else
            {
                _logger.LogWarning("Failed to send heartbeat - no response received");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending heartbeat");
        }
    }

    private async Task<SystemInfo> GetSystemInfoAsync()
    {
        try
        {
            var systemInfo = new SystemInfo
            {
                MachineName = Environment.MachineName,
                OperatingSystem = Environment.OSVersion.ToString(),
                ProcessorCount = Environment.ProcessorCount,
                TotalMemoryMB = await GetTotalMemoryAsync(),
                AvailableMemoryMB = await GetAvailableMemoryAsync(),
                DiskSpaceGB = await GetDiskSpaceAsync(),
                Uptime = TimeSpan.FromMilliseconds(Environment.TickCount64),
                LastBootTime = DateTime.Now.Subtract(TimeSpan.FromMilliseconds(Environment.TickCount64))
            };

            return systemInfo;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error getting system information");
            return new SystemInfo
            {
                MachineName = Environment.MachineName,
                OperatingSystem = Environment.OSVersion.ToString(),
                ProcessorCount = Environment.ProcessorCount
            };
        }
    }

    private async Task<long> GetTotalMemoryAsync()
    {
        try
        {
            return await Task.Run(() =>
            {
                using var searcher = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return Convert.ToInt64(obj["TotalPhysicalMemory"]) / (1024 * 1024); // Convert to MB
                }
                return 0;
            });
        }
        catch
        {
            return 0;
        }
    }

    private async Task<long> GetAvailableMemoryAsync()
    {
        try
        {
            return await Task.Run(() =>
            {
                using var searcher = new ManagementObjectSearcher("SELECT AvailableBytes FROM Win32_PerfRawData_PerfOS_Memory");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return Convert.ToInt64(obj["AvailableBytes"]) / (1024 * 1024); // Convert to MB
                }
                return 0;
            });
        }
        catch
        {
            return 0;
        }
    }

    private async Task<long> GetDiskSpaceAsync()
    {
        try
        {
            return await Task.Run(() =>
            {
                var drive = new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory)!);
                return drive.AvailableFreeSpace / (1024 * 1024 * 1024); // Convert to GB
            });
        }
        catch
        {
            return 0;
        }
    }

    private async Task TriggerSyncAsync(string syncType)
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var syncService = scope.ServiceProvider.GetService<SynchronizationService>();
            
            if (syncService != null)
            {
                switch (syncType.ToLower())
                {
                    case "users":
                        await syncService.SyncUsersAsync();
                        break;
                    case "groups":
                        await syncService.SyncGroupsAsync();
                        break;
                    case "full":
                        await syncService.SyncUsersAsync();
                        await syncService.SyncGroupsAsync();
                        break;
                    default:
                        _logger.LogWarning("Unknown sync type requested: {SyncType}", syncType);
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error triggering sync for type: {SyncType}", syncType);
        }
    }

    private async Task ProcessCommandsAsync(List<AgentCommand> commands)
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var commandProcessor = scope.ServiceProvider.GetService<CommandProcessorService>();
            
            if (commandProcessor != null)
            {
                foreach (var command in commands)
                {
                    try
                    {
                        await commandProcessor.ProcessCommandAsync(command);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error processing command {CommandId}", command.Id);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing commands");
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Heartbeat service is stopping");
        await base.StopAsync(cancellationToken);
    }
}