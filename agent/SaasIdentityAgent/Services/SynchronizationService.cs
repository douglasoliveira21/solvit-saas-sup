using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SaasIdentityAgent.Models;

namespace SaasIdentityAgent.Services;

public class SynchronizationService : BackgroundService
{
    private readonly ILogger<SynchronizationService> _logger;
    private readonly IServiceProvider _serviceProvider;
    private readonly AgentConfiguration _config;
    private DateTime _lastUserSync = DateTime.MinValue;
    private DateTime _lastGroupSync = DateTime.MinValue;

    public SynchronizationService(
        ILogger<SynchronizationService> logger,
        IServiceProvider serviceProvider,
        IOptions<AgentConfiguration> config)
    {
        _logger = logger;
        _serviceProvider = serviceProvider;
        _config = config.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Synchronization service started");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var now = DateTime.UtcNow;
                
                // Check if it's time for user sync
                if (now.Subtract(_lastUserSync).TotalSeconds >= _config.SyncIntervalSeconds)
                {
                    await SyncUsersAsync();
                    _lastUserSync = now;
                }

                // Check if it's time for group sync
                if (now.Subtract(_lastGroupSync).TotalSeconds >= _config.SyncIntervalSeconds)
                {
                    await SyncGroupsAsync();
                    _lastGroupSync = now;
                }

                await Task.Delay(TimeSpan.FromSeconds(60), stoppingToken); // Check every minute
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Synchronization service is stopping");
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in synchronization service");
                await Task.Delay(TimeSpan.FromSeconds(60), stoppingToken);
            }
        }
    }

    public async Task SyncUsersAsync()
    {
        try
        {
            _logger.LogInformation("Starting user synchronization");
            
            using var scope = _serviceProvider.CreateScope();
            var adService = scope.ServiceProvider.GetRequiredService<IActiveDirectoryService>();
            var backendApi = scope.ServiceProvider.GetRequiredService<IBackendApiService>();

            // Get users from Active Directory
            var adUsers = await adService.GetUsersAsync();
            
            if (!adUsers.Any())
            {
                _logger.LogWarning("No users found in Active Directory");
                return;
            }

            // Filter users based on configuration
            var filteredUsers = FilterUsers(adUsers);
            
            _logger.LogInformation("Found {TotalUsers} users in AD, {FilteredUsers} after filtering", 
                adUsers.Count, filteredUsers.Count);

            // Send users to backend in batches
            const int batchSize = 100;
            var batches = filteredUsers.Chunk(batchSize);
            
            foreach (var batch in batches)
            {
                try
                {
                    var syncRequest = new UserSyncRequest
                    {
                        AgentId = _config.AgentId,
                        TenantId = _config.TenantId,
                        SyncTimestamp = DateTime.UtcNow,
                        Users = batch.ToList()
                    };

                    var success = await backendApi.SyncUsersAsync(syncRequest);
                    
                    if (success)
                    {
                        _logger.LogDebug("Successfully synced batch of {Count} users", batch.Count());
                    }
                    else
                    {
                        _logger.LogWarning("Failed to sync batch of {Count} users", batch.Count());
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error syncing user batch");
                }
            }

            _logger.LogInformation("User synchronization completed");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during user synchronization");
        }
    }

    public async Task SyncGroupsAsync()
    {
        try
        {
            _logger.LogInformation("Starting group synchronization");
            
            using var scope = _serviceProvider.CreateScope();
            var adService = scope.ServiceProvider.GetRequiredService<IActiveDirectoryService>();
            var backendApi = scope.ServiceProvider.GetRequiredService<IBackendApiService>();

            // Get groups from Active Directory
            var adGroups = await adService.GetGroupsAsync();
            
            if (!adGroups.Any())
            {
                _logger.LogWarning("No groups found in Active Directory");
                return;
            }

            // Filter groups based on configuration
            var filteredGroups = FilterGroups(adGroups);
            
            _logger.LogInformation("Found {TotalGroups} groups in AD, {FilteredGroups} after filtering", 
                adGroups.Count, filteredGroups.Count);

            // Send groups to backend in batches
            const int batchSize = 50;
            var batches = filteredGroups.Chunk(batchSize);
            
            foreach (var batch in batches)
            {
                try
                {
                    var syncRequest = new GroupSyncRequest
                    {
                        AgentId = _config.AgentId,
                        TenantId = _config.TenantId,
                        SyncTimestamp = DateTime.UtcNow,
                        Groups = batch.ToList()
                    };

                    var success = await backendApi.SyncGroupsAsync(syncRequest);
                    
                    if (success)
                    {
                        _logger.LogDebug("Successfully synced batch of {Count} groups", batch.Count());
                    }
                    else
                    {
                        _logger.LogWarning("Failed to sync batch of {Count} groups", batch.Count());
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error syncing group batch");
                }
            }

            _logger.LogInformation("Group synchronization completed");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during group synchronization");
        }
    }

    private List<ADUser> FilterUsers(List<ADUser> users)
    {
        var filtered = users.AsEnumerable();

        // Filter by OUs to sync
        if (_config.ActiveDirectory.OrganizationalUnitsToSync?.Any() == true)
        {
            filtered = filtered.Where(u => 
                _config.ActiveDirectory.OrganizationalUnitsToSync.Any(ou => 
                    u.DistinguishedName.Contains(ou, StringComparison.OrdinalIgnoreCase)));
        }

        // Exclude specific OUs
        if (_config.ActiveDirectory.OrganizationalUnitsToExclude?.Any() == true)
        {
            filtered = filtered.Where(u => 
                !_config.ActiveDirectory.OrganizationalUnitsToExclude.Any(ou => 
                    u.DistinguishedName.Contains(ou, StringComparison.OrdinalIgnoreCase)));
        }

        // Filter out system accounts and service accounts
        filtered = filtered.Where(u => 
            !string.IsNullOrEmpty(u.Username) &&
            !u.Username.StartsWith("$") && // Computer accounts
            !u.Username.StartsWith("krbtgt") && // Kerberos accounts
            !u.Username.StartsWith("MSOL_") && // Microsoft Online accounts
            !u.Username.Contains("HealthMailbox") && // Exchange health mailboxes
            !u.Username.Contains("SystemMailbox") && // Exchange system mailboxes
            u.Username.Length > 1);

        // Only include enabled users (optional - can be configured)
        if (_config.SyncOnlyEnabledUsers)
        {
            filtered = filtered.Where(u => u.IsEnabled);
        }

        return filtered.ToList();
    }

    private List<ADGroup> FilterGroups(List<ADGroup> groups)
    {
        var filtered = groups.AsEnumerable();

        // Filter by OUs to sync
        if (_config.ActiveDirectory.OrganizationalUnitsToSync?.Any() == true)
        {
            filtered = filtered.Where(g => 
                _config.ActiveDirectory.OrganizationalUnitsToSync.Any(ou => 
                    g.DistinguishedName.Contains(ou, StringComparison.OrdinalIgnoreCase)));
        }

        // Exclude specific OUs
        if (_config.ActiveDirectory.OrganizationalUnitsToExclude?.Any() == true)
        {
            filtered = filtered.Where(g => 
                !_config.ActiveDirectory.OrganizationalUnitsToExclude.Any(ou => 
                    g.DistinguishedName.Contains(ou, StringComparison.OrdinalIgnoreCase)));
        }

        // Filter out built-in groups
        var builtInGroups = new[]
        {
            "Domain Admins", "Domain Users", "Domain Guests", "Domain Controllers",
            "Schema Admins", "Enterprise Admins", "Cert Publishers", "Domain Computers",
            "Administrators", "Users", "Guests", "Power Users", "Account Operators",
            "Server Operators", "Print Operators", "Backup Operators", "Replicator",
            "Network Configuration Operators", "Performance Monitor Users", "Performance Log Users",
            "Distributed COM Users", "IIS_IUSRS", "Cryptographic Operators", "Event Log Readers",
            "Certificate Service DCOM Access", "RDS Remote Access Servers", "RDS Endpoint Servers",
            "RDS Management Servers", "Hyper-V Administrators", "Access Control Assistance Operators",
            "Remote Management Users", "Storage Replica Administrators"
        };

        filtered = filtered.Where(g => 
            !string.IsNullOrEmpty(g.Name) &&
            !builtInGroups.Contains(g.Name, StringComparer.OrdinalIgnoreCase) &&
            !g.Name.StartsWith("BUILTIN\\") &&
            !g.Name.StartsWith("NT AUTHORITY\\"));

        return filtered.ToList();
    }

    public async Task<SyncResult> GetSyncStatusAsync()
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var adService = scope.ServiceProvider.GetRequiredService<IActiveDirectoryService>();

            var adConnected = await adService.TestConnectionAsync();
            
            return new SyncResult
            {
                Success = adConnected,
                Message = adConnected ? "Active Directory connection successful" : "Active Directory connection failed",
                LastUserSync = _lastUserSync,
                LastGroupSync = _lastGroupSync,
                NextUserSync = _lastUserSync.AddSeconds(_config.SyncIntervalSeconds),
                NextGroupSync = _lastGroupSync.AddSeconds(_config.SyncIntervalSeconds)
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting sync status");
            return new SyncResult
            {
                Success = false,
                Message = $"Error: {ex.Message}",
                LastUserSync = _lastUserSync,
                LastGroupSync = _lastGroupSync
            };
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Synchronization service is stopping");
        await base.StopAsync(cancellationToken);
    }
}