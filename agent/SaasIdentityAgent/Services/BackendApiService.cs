using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using SaasIdentityAgent.Models;
using System.Net;
using System.Net.Http.Headers;
using System.Text;

namespace SaasIdentityAgent.Services;

public interface IBackendApiService
{
    Task<HeartbeatResponse?> SendHeartbeatAsync(HeartbeatRequest request, CancellationToken cancellationToken = default);
    Task<ConfigurationResponse?> GetConfigurationAsync(CancellationToken cancellationToken = default);
    Task<bool> SyncUsersAsync(UserSyncRequest request, CancellationToken cancellationToken = default);
    Task<bool> SyncGroupsAsync(GroupSyncRequest request, CancellationToken cancellationToken = default);
    Task<bool> SendLogsAsync(AgentLogRequest request, CancellationToken cancellationToken = default);
    Task<bool> SendCommandResultAsync(CommandResult result, CancellationToken cancellationToken = default);
}

public class BackendApiService : IBackendApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<BackendApiService> _logger;
    private readonly BackendConfiguration _config;
    private readonly AgentConfiguration _agentConfig;

    public BackendApiService(
        HttpClient httpClient,
        ILogger<BackendApiService> logger,
        IOptions<BackendConfiguration> config,
        IOptions<AgentConfiguration> agentConfig)
    {
        _httpClient = httpClient;
        _logger = logger;
        _config = config.Value;
        _agentConfig = agentConfig.Value;
        
        ConfigureHttpClient();
    }

    private void ConfigureHttpClient()
    {
        // Set API Key header
        _httpClient.DefaultRequestHeaders.Clear();
        _httpClient.DefaultRequestHeaders.Add("Agent-Key", _config.ApiKey);
        _httpClient.DefaultRequestHeaders.Add("User-Agent", $"SaasIdentityAgent/{_agentConfig.Version}");
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        
        // Configure timeout
        _httpClient.Timeout = TimeSpan.FromSeconds(_config.TimeoutSeconds);
        
        // Configure proxy if specified
        if (!string.IsNullOrEmpty(_config.ProxyUrl))
        {
            var handler = new HttpClientHandler()
            {
                Proxy = new WebProxy(_config.ProxyUrl)
            };
            
            if (!string.IsNullOrEmpty(_config.ProxyUsername))
            {
                handler.Proxy.Credentials = new NetworkCredential(_config.ProxyUsername, _config.ProxyPassword);
            }
        }
        
        // SSL Certificate validation
        if (!_config.ValidateSslCertificate)
        {
            _logger.LogWarning("SSL certificate validation is disabled. This should only be used in development.");
        }
    }

    public async Task<HeartbeatResponse?> SendHeartbeatAsync(HeartbeatRequest request, CancellationToken cancellationToken = default)
    {
        return await ExecuteWithRetryAsync(async () =>
        {
            var response = await PostAsync<HeartbeatRequest, HeartbeatResponse>(
                "api/agent/heartbeat/", request, cancellationToken);
            
            _logger.LogDebug("Heartbeat sent successfully");
            return response;
        }, "SendHeartbeat");
    }

    public async Task<ConfigurationResponse?> GetConfigurationAsync(CancellationToken cancellationToken = default)
    {
        return await ExecuteWithRetryAsync(async () =>
        {
            var response = await GetAsync<ConfigurationResponse>(
                "api/agent/config/", cancellationToken);
            
            _logger.LogDebug("Configuration retrieved successfully");
            return response;
        }, "GetConfiguration");
    }

    public async Task<bool> SyncUsersAsync(UserSyncRequest request, CancellationToken cancellationToken = default)
    {
        return await ExecuteWithRetryAsync(async () =>
        {
            var response = await PostAsync<UserSyncRequest, object>(
                "api/agent/sync/sync_users/", request, cancellationToken);
            
            _logger.LogInformation($"Synced {request.Users.Count} users successfully");
            return true;
        }, "SyncUsers");
    }

    public async Task<bool> SyncGroupsAsync(GroupSyncRequest request, CancellationToken cancellationToken = default)
    {
        return await ExecuteWithRetryAsync(async () =>
        {
            var response = await PostAsync<GroupSyncRequest, object>(
                "api/agent/sync/sync_groups/", request, cancellationToken);
            
            _logger.LogInformation($"Synced {request.Groups.Count} groups successfully");
            return true;
        }, "SyncGroups");
    }

    public async Task<bool> SendLogsAsync(AgentLogRequest request, CancellationToken cancellationToken = default)
    {
        return await ExecuteWithRetryAsync(async () =>
        {
            var response = await PostAsync<AgentLogRequest, object>(
                "api/agent/logs/", request, cancellationToken);
            
            _logger.LogDebug($"Sent {request.Logs.Count} log entries to backend");
            return true;
        }, "SendLogs");
    }

    public async Task<bool> SendCommandResultAsync(CommandResult result, CancellationToken cancellationToken = default)
    {
        return await ExecuteWithRetryAsync(async () =>
        {
            var response = await PostAsync<CommandResult, object>(
                $"api/agent/commands/{result.CommandId}/result/", result, cancellationToken);
            
            _logger.LogDebug($"Command result sent for command {result.CommandId}");
            return true;
        }, "SendCommandResult");
    }

    private async Task<TResponse?> GetAsync<TResponse>(string endpoint, CancellationToken cancellationToken)
        where TResponse : class
    {
        try
        {
            var response = await _httpClient.GetAsync(endpoint, cancellationToken);
            
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync(cancellationToken);
                return JsonConvert.DeserializeObject<TResponse>(content);
            }
            
            await LogErrorResponse(response, endpoint);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during GET request to {Endpoint}", endpoint);
            throw;
        }
    }

    private async Task<TResponse?> PostAsync<TRequest, TResponse>(
        string endpoint, 
        TRequest request, 
        CancellationToken cancellationToken)
        where TResponse : class
    {
        try
        {
            var json = JsonConvert.SerializeObject(request, Formatting.None);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            
            var response = await _httpClient.PostAsync(endpoint, content, cancellationToken);
            
            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
                
                if (typeof(TResponse) == typeof(object))
                {
                    return new object() as TResponse;
                }
                
                return JsonConvert.DeserializeObject<TResponse>(responseContent);
            }
            
            await LogErrorResponse(response, endpoint);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during POST request to {Endpoint}", endpoint);
            throw;
        }
    }

    private async Task<T> ExecuteWithRetryAsync<T>(Func<Task<T>> operation, string operationName)
    {
        var maxRetries = _agentConfig.MaxRetryAttempts;
        var retryDelay = TimeSpan.FromSeconds(_agentConfig.RetryDelaySeconds);
        
        for (int attempt = 1; attempt <= maxRetries; attempt++)
        {
            try
            {
                return await operation();
            }
            catch (Exception ex) when (attempt < maxRetries)
            {
                _logger.LogWarning(ex, 
                    "Attempt {Attempt}/{MaxRetries} failed for {Operation}. Retrying in {Delay}s...",
                    attempt, maxRetries, operationName, retryDelay.TotalSeconds);
                
                await Task.Delay(retryDelay);
                retryDelay = TimeSpan.FromSeconds(retryDelay.TotalSeconds * 2); // Exponential backoff
            }
        }
        
        // Final attempt without catching exception
        return await operation();
    }

    private async Task LogErrorResponse(HttpResponseMessage response, string endpoint)
    {
        var content = await response.Content.ReadAsStringAsync();
        _logger.LogError(
            "HTTP {StatusCode} error for {Endpoint}: {Content}",
            response.StatusCode, endpoint, content);
    }
}