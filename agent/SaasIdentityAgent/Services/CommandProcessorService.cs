using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using SaasIdentityAgent.Models;
using System.Collections.Concurrent;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace SaasIdentityAgent.Services;

public class CommandProcessorService : BackgroundService
{
    private readonly ILogger<CommandProcessorService> _logger;
    private readonly IServiceProvider _serviceProvider;
    private readonly AgentConfiguration _config;
    private readonly ConcurrentQueue<AgentCommand> _commandQueue = new();
    private readonly SemaphoreSlim _processingLock = new(1, 1);

    public CommandProcessorService(
        ILogger<CommandProcessorService> logger,
        IServiceProvider serviceProvider,
        IOptions<AgentConfiguration> config)
    {
        _logger = logger;
        _serviceProvider = serviceProvider;
        _config = config.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Command processor service started");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (_commandQueue.TryDequeue(out var command))
                {
                    await ProcessCommandAsync(command);
                }
                else
                {
                    await Task.Delay(TimeSpan.FromSeconds(_config.CommandCheckIntervalSeconds), stoppingToken);
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Command processor service is stopping");
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in command processor service");
                await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
            }
        }
    }

    public async Task ProcessCommandAsync(AgentCommand command)
    {
        if (command == null)
        {
            _logger.LogWarning("Received null command");
            return;
        }

        await _processingLock.WaitAsync();
        
        try
        {
            _logger.LogInformation("Processing command {CommandId} of type {CommandType}", 
                command.Id, command.CommandType);

            var result = new CommandResult
            {
                CommandId = command.Id,
                AgentId = _config.AgentId,
                StartTime = DateTime.UtcNow,
                Status = "processing"
            };

            try
            {
                switch (command.CommandType.ToLower())
                {
                    case "create_user":
                        result = await ProcessCreateUserCommand(command);
                        break;
                    case "update_user":
                        result = await ProcessUpdateUserCommand(command);
                        break;
                    case "disable_user":
                        result = await ProcessDisableUserCommand(command);
                        break;
                    case "enable_user":
                        result = await ProcessEnableUserCommand(command);
                        break;
                    case "delete_user":
                        result = await ProcessDeleteUserCommand(command);
                        break;
                    case "add_user_to_group":
                        result = await ProcessAddUserToGroupCommand(command);
                        break;
                    case "remove_user_from_group":
                        result = await ProcessRemoveUserFromGroupCommand(command);
                        break;
                    case "create_group":
                        result = await ProcessCreateGroupCommand(command);
                        break;
                    case "sync_now":
                        result = await ProcessSyncNowCommand(command);
                        break;
                    case "powershell":
                        result = await ProcessPowerShellCommand(command);
                        break;
                    case "test_connection":
                        result = await ProcessTestConnectionCommand(command);
                        break;
                    default:
                        result.Status = "failed";
                        result.ErrorMessage = $"Unknown command type: {command.CommandType}";
                        _logger.LogWarning("Unknown command type: {CommandType}", command.CommandType);
                        break;
                }
            }
            catch (Exception ex)
            {
                result.Status = "failed";
                result.ErrorMessage = ex.Message;
                result.Output = ex.ToString();
                _logger.LogError(ex, "Error executing command {CommandId}", command.Id);
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime.Value.Subtract(result.StartTime);
                
                // Send result back to backend
                await SendCommandResultAsync(result);
            }
        }
        finally
        {
            _processingLock.Release();
        }
    }

    private async Task<CommandResult> ProcessCreateUserCommand(AgentCommand command)
    {
        var result = CreateCommandResult(command);
        
        try
        {
            var parameters = JsonConvert.DeserializeObject<Dictionary<string, object>>(command.Parameters ?? "{}");
            
            var username = parameters.GetValueOrDefault("username")?.ToString();
            var firstName = parameters.GetValueOrDefault("firstName")?.ToString();
            var lastName = parameters.GetValueOrDefault("lastName")?.ToString();
            var email = parameters.GetValueOrDefault("email")?.ToString();
            var password = parameters.GetValueOrDefault("password")?.ToString();
            var ou = parameters.GetValueOrDefault("organizationalUnit")?.ToString();

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(firstName) || 
                string.IsNullOrEmpty(lastName) || string.IsNullOrEmpty(password))
            {
                result.Status = "failed";
                result.ErrorMessage = "Missing required parameters: username, firstName, lastName, password";
                return result;
            }

            using var scope = _serviceProvider.CreateScope();
            var adService = scope.ServiceProvider.GetRequiredService<IActiveDirectoryService>();
            
            var success = await adService.CreateUserAsync(username, firstName, lastName, email ?? "", password, ou);
            
            result.Status = success ? "completed" : "failed";
            result.Output = success ? $"User {username} created successfully" : $"Failed to create user {username}";
            
            if (!success)
            {
                result.ErrorMessage = "User creation failed";
            }
        }
        catch (Exception ex)
        {
            result.Status = "failed";
            result.ErrorMessage = ex.Message;
        }
        
        return result;
    }

    private async Task<CommandResult> ProcessUpdateUserCommand(AgentCommand command)
    {
        var result = CreateCommandResult(command);
        
        try
        {
            var parameters = JsonConvert.DeserializeObject<Dictionary<string, object>>(command.Parameters ?? "{}");
            
            var username = parameters.GetValueOrDefault("username")?.ToString();
            
            if (string.IsNullOrEmpty(username))
            {
                result.Status = "failed";
                result.ErrorMessage = "Missing required parameter: username";
                return result;
            }

            // Remove username from parameters to get update properties
            parameters.Remove("username");

            using var scope = _serviceProvider.CreateScope();
            var adService = scope.ServiceProvider.GetRequiredService<IActiveDirectoryService>();
            
            var success = await adService.UpdateUserAsync(username, parameters);
            
            result.Status = success ? "completed" : "failed";
            result.Output = success ? $"User {username} updated successfully" : $"Failed to update user {username}";
            
            if (!success)
            {
                result.ErrorMessage = "User update failed";
            }
        }
        catch (Exception ex)
        {
            result.Status = "failed";
            result.ErrorMessage = ex.Message;
        }
        
        return result;
    }

    private async Task<CommandResult> ProcessDisableUserCommand(AgentCommand command)
    {
        var result = CreateCommandResult(command);
        
        try
        {
            var parameters = JsonConvert.DeserializeObject<Dictionary<string, object>>(command.Parameters ?? "{}");
            var username = parameters.GetValueOrDefault("username")?.ToString();

            if (string.IsNullOrEmpty(username))
            {
                result.Status = "failed";
                result.ErrorMessage = "Missing required parameter: username";
                return result;
            }

            using var scope = _serviceProvider.CreateScope();
            var adService = scope.ServiceProvider.GetRequiredService<IActiveDirectoryService>();
            
            var success = await adService.DisableUserAsync(username);
            
            result.Status = success ? "completed" : "failed";
            result.Output = success ? $"User {username} disabled successfully" : $"Failed to disable user {username}";
            
            if (!success)
            {
                result.ErrorMessage = "User disable failed";
            }
        }
        catch (Exception ex)
        {
            result.Status = "failed";
            result.ErrorMessage = ex.Message;
        }
        
        return result;
    }

    private async Task<CommandResult> ProcessEnableUserCommand(AgentCommand command)
    {
        var result = CreateCommandResult(command);
        
        try
        {
            var parameters = JsonConvert.DeserializeObject<Dictionary<string, object>>(command.Parameters ?? "{}");
            var username = parameters.GetValueOrDefault("username")?.ToString();

            if (string.IsNullOrEmpty(username))
            {
                result.Status = "failed";
                result.ErrorMessage = "Missing required parameter: username";
                return result;
            }

            using var scope = _serviceProvider.CreateScope();
            var adService = scope.ServiceProvider.GetRequiredService<IActiveDirectoryService>();
            
            var success = await adService.EnableUserAsync(username);
            
            result.Status = success ? "completed" : "failed";
            result.Output = success ? $"User {username} enabled successfully" : $"Failed to enable user {username}";
            
            if (!success)
            {
                result.ErrorMessage = "User enable failed";
            }
        }
        catch (Exception ex)
        {
            result.Status = "failed";
            result.ErrorMessage = ex.Message;
        }
        
        return result;
    }

    private async Task<CommandResult> ProcessDeleteUserCommand(AgentCommand command)
    {
        var result = CreateCommandResult(command);
        
        try
        {
            var parameters = JsonConvert.DeserializeObject<Dictionary<string, object>>(command.Parameters ?? "{}");
            var username = parameters.GetValueOrDefault("username")?.ToString();

            if (string.IsNullOrEmpty(username))
            {
                result.Status = "failed";
                result.ErrorMessage = "Missing required parameter: username";
                return result;
            }

            using var scope = _serviceProvider.CreateScope();
            var adService = scope.ServiceProvider.GetRequiredService<IActiveDirectoryService>();
            
            var success = await adService.DeleteUserAsync(username);
            
            result.Status = success ? "completed" : "failed";
            result.Output = success ? $"User {username} deleted successfully" : $"Failed to delete user {username}";
            
            if (!success)
            {
                result.ErrorMessage = "User deletion failed";
            }
        }
        catch (Exception ex)
        {
            result.Status = "failed";
            result.ErrorMessage = ex.Message;
        }
        
        return result;
    }

    private async Task<CommandResult> ProcessAddUserToGroupCommand(AgentCommand command)
    {
        var result = CreateCommandResult(command);
        
        try
        {
            var parameters = JsonConvert.DeserializeObject<Dictionary<string, object>>(command.Parameters ?? "{}");
            var username = parameters.GetValueOrDefault("username")?.ToString();
            var groupName = parameters.GetValueOrDefault("groupName")?.ToString();

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(groupName))
            {
                result.Status = "failed";
                result.ErrorMessage = "Missing required parameters: username, groupName";
                return result;
            }

            using var scope = _serviceProvider.CreateScope();
            var adService = scope.ServiceProvider.GetRequiredService<IActiveDirectoryService>();
            
            var success = await adService.AddUserToGroupAsync(username, groupName);
            
            result.Status = success ? "completed" : "failed";
            result.Output = success ? $"User {username} added to group {groupName} successfully" : 
                                    $"Failed to add user {username} to group {groupName}";
            
            if (!success)
            {
                result.ErrorMessage = "Add user to group failed";
            }
        }
        catch (Exception ex)
        {
            result.Status = "failed";
            result.ErrorMessage = ex.Message;
        }
        
        return result;
    }

    private async Task<CommandResult> ProcessRemoveUserFromGroupCommand(AgentCommand command)
    {
        var result = CreateCommandResult(command);
        
        try
        {
            // This would require implementing RemoveUserFromGroupAsync in ActiveDirectoryService
            result.Status = "failed";
            result.ErrorMessage = "Remove user from group not implemented yet";
        }
        catch (Exception ex)
        {
            result.Status = "failed";
            result.ErrorMessage = ex.Message;
        }
        
        return result;
    }

    private async Task<CommandResult> ProcessCreateGroupCommand(AgentCommand command)
    {
        var result = CreateCommandResult(command);
        
        try
        {
            var parameters = JsonConvert.DeserializeObject<Dictionary<string, object>>(command.Parameters ?? "{}");
            var groupName = parameters.GetValueOrDefault("groupName")?.ToString();
            var description = parameters.GetValueOrDefault("description")?.ToString();
            var ou = parameters.GetValueOrDefault("organizationalUnit")?.ToString();

            if (string.IsNullOrEmpty(groupName))
            {
                result.Status = "failed";
                result.ErrorMessage = "Missing required parameter: groupName";
                return result;
            }

            using var scope = _serviceProvider.CreateScope();
            var adService = scope.ServiceProvider.GetRequiredService<IActiveDirectoryService>();
            
            var success = await adService.CreateGroupAsync(groupName, description, ou);
            
            result.Status = success ? "completed" : "failed";
            result.Output = success ? $"Group {groupName} created successfully" : $"Failed to create group {groupName}";
            
            if (!success)
            {
                result.ErrorMessage = "Group creation failed";
            }
        }
        catch (Exception ex)
        {
            result.Status = "failed";
            result.ErrorMessage = ex.Message;
        }
        
        return result;
    }

    private async Task<CommandResult> ProcessSyncNowCommand(AgentCommand command)
    {
        var result = CreateCommandResult(command);
        
        try
        {
            var parameters = JsonConvert.DeserializeObject<Dictionary<string, object>>(command.Parameters ?? "{}");
            var syncType = parameters.GetValueOrDefault("syncType")?.ToString() ?? "full";

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
                    default:
                        await syncService.SyncUsersAsync();
                        await syncService.SyncGroupsAsync();
                        break;
                }
                
                result.Status = "completed";
                result.Output = $"Sync {syncType} completed successfully";
            }
            else
            {
                result.Status = "failed";
                result.ErrorMessage = "Synchronization service not available";
            }
        }
        catch (Exception ex)
        {
            result.Status = "failed";
            result.ErrorMessage = ex.Message;
        }
        
        return result;
    }

    private async Task<CommandResult> ProcessPowerShellCommand(AgentCommand command)
    {
        var result = CreateCommandResult(command);
        
        try
        {
            var parameters = JsonConvert.DeserializeObject<Dictionary<string, object>>(command.Parameters ?? "{}");
            var script = parameters.GetValueOrDefault("script")?.ToString();

            if (string.IsNullOrEmpty(script))
            {
                result.Status = "failed";
                result.ErrorMessage = "Missing required parameter: script";
                return result;
            }

            var output = await ExecutePowerShellAsync(script);
            
            result.Status = "completed";
            result.Output = output;
        }
        catch (Exception ex)
        {
            result.Status = "failed";
            result.ErrorMessage = ex.Message;
        }
        
        return result;
    }

    private async Task<CommandResult> ProcessTestConnectionCommand(AgentCommand command)
    {
        var result = CreateCommandResult(command);
        
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var adService = scope.ServiceProvider.GetRequiredService<IActiveDirectoryService>();
            
            var success = await adService.TestConnectionAsync();
            
            result.Status = "completed";
            result.Output = success ? "Active Directory connection successful" : "Active Directory connection failed";
        }
        catch (Exception ex)
        {
            result.Status = "failed";
            result.ErrorMessage = ex.Message;
        }
        
        return result;
    }

    private async Task<string> ExecutePowerShellAsync(string script)
    {
        return await Task.Run(() =>
        {
            using var runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            
            using var pipeline = runspace.CreatePipeline();
            pipeline.Commands.AddScript(script);
            
            var results = pipeline.Invoke();
            var output = string.Join(Environment.NewLine, results.Select(r => r.ToString()));
            
            if (pipeline.Error.Count > 0)
            {
                var errors = string.Join(Environment.NewLine, pipeline.Error.ReadToEnd().Select(e => e.ToString()));
                throw new Exception($"PowerShell errors: {errors}");
            }
            
            return output;
        });
    }

    private CommandResult CreateCommandResult(AgentCommand command)
    {
        return new CommandResult
        {
            CommandId = command.Id,
            AgentId = _config.AgentId,
            StartTime = DateTime.UtcNow,
            Status = "processing"
        };
    }

    private async Task SendCommandResultAsync(CommandResult result)
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var backendApi = scope.ServiceProvider.GetRequiredService<IBackendApiService>();
            
            await backendApi.SendCommandResultAsync(result);
            
            _logger.LogInformation("Command result sent for command {CommandId} with status {Status}", 
                result.CommandId, result.Status);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending command result for command {CommandId}", result.CommandId);
        }
    }

    public void QueueCommand(AgentCommand command)
    {
        _commandQueue.Enqueue(command);
        _logger.LogInformation("Command {CommandId} queued for processing", command.Id);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Command processor service is stopping");
        await base.StopAsync(cancellationToken);
    }
}