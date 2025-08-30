using System.ComponentModel.DataAnnotations;

namespace SaasIdentityAgent.Models;

public class AgentConfiguration
{
    [Required]
    public string AgentId { get; set; } = string.Empty;
    
    [Required]
    public string TenantId { get; set; } = string.Empty;
    
    public string Version { get; set; } = "1.0.0";
    
    public int HeartbeatIntervalSeconds { get; set; } = 60;
    
    public int SyncIntervalMinutes { get; set; } = 15;
    
    public int CommandCheckIntervalSeconds { get; set; } = 30;
    
    public int MaxRetryAttempts { get; set; } = 3;
    
    public int RetryDelaySeconds { get; set; } = 5;
    
    public bool EnableDetailedLogging { get; set; } = false;
}

public class BackendConfiguration
{
    [Required]
    public string BaseUrl { get; set; } = string.Empty;
    
    [Required]
    public string ApiKey { get; set; } = string.Empty;
    
    public int TimeoutSeconds { get; set; } = 30;
    
    public bool ValidateSslCertificate { get; set; } = true;
    
    public string? ProxyUrl { get; set; }
    
    public string? ProxyUsername { get; set; }
    
    public string? ProxyPassword { get; set; }
}

public class ActiveDirectoryConfiguration
{
    [Required]
    public string Domain { get; set; } = string.Empty;
    
    [Required]
    public string ServiceAccountUsername { get; set; } = string.Empty;
    
    [Required]
    public string ServiceAccountPassword { get; set; } = string.Empty;
    
    public string? DomainController { get; set; }
    
    public string DefaultUserContainer { get; set; } = "CN=Users";
    
    public string DefaultGroupContainer { get; set; } = "CN=Users";
    
    public bool UseSecureConnection { get; set; } = true;
    
    public int LdapPort { get; set; } = 636; // LDAPS port
    
    public int ConnectionTimeoutSeconds { get; set; } = 30;
    
    public string[] SyncOUs { get; set; } = Array.Empty<string>();
    
    public string[] ExcludeOUs { get; set; } = Array.Empty<string>();
}