using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;

namespace SaasIdentityAgent.Models;

// Heartbeat Models
public class HeartbeatRequest
{
    [JsonProperty("agent_version")]
    public string AgentVersion { get; set; } = string.Empty;
    
    [JsonProperty("status")]
    public string Status { get; set; } = "running";
    
    [JsonProperty("system_info")]
    public SystemInfo SystemInfo { get; set; } = new();
    
    [JsonProperty("last_sync_timestamp")]
    public DateTime? LastSyncTimestamp { get; set; }
    
    [JsonProperty("error_message")]
    public string? ErrorMessage { get; set; }
}

public class SystemInfo
{
    [JsonProperty("os")]
    public string OperatingSystem { get; set; } = string.Empty;
    
    [JsonProperty("hostname")]
    public string Hostname { get; set; } = string.Empty;
    
    [JsonProperty("domain")]
    public string Domain { get; set; } = string.Empty;
    
    [JsonProperty("cpu_usage")]
    public double CpuUsage { get; set; }
    
    [JsonProperty("memory_usage")]
    public double MemoryUsage { get; set; }
    
    [JsonProperty("disk_usage")]
    public double DiskUsage { get; set; }
}

public class HeartbeatResponse
{
    [JsonProperty("status")]
    public string Status { get; set; } = string.Empty;
    
    [JsonProperty("message")]
    public string Message { get; set; } = string.Empty;
    
    [JsonProperty("configuration_updated")]
    public bool ConfigurationUpdated { get; set; }
    
    [JsonProperty("pending_sync")]
    public PendingSync? PendingSync { get; set; }
    
    [JsonProperty("commands")]
    public List<AgentCommand> Commands { get; set; } = new();
}

public class PendingSync
{
    [JsonProperty("users")]
    public bool Users { get; set; }
    
    [JsonProperty("groups")]
    public bool Groups { get; set; }
    
    [JsonProperty("timestamp")]
    public DateTime Timestamp { get; set; }
}

// Configuration Models
public class ConfigurationResponse
{
    [JsonProperty("domain")]
    public string Domain { get; set; } = string.Empty;
    
    [JsonProperty("service_account_username")]
    public string ServiceAccountUsername { get; set; } = string.Empty;
    
    [JsonProperty("service_account_password")]
    public string ServiceAccountPassword { get; set; } = string.Empty;
    
    [JsonProperty("sync_interval_minutes")]
    public int SyncIntervalMinutes { get; set; }
    
    [JsonProperty("sync_ous")]
    public List<string> SyncOUs { get; set; } = new();
    
    [JsonProperty("exclude_ous")]
    public List<string> ExcludeOUs { get; set; } = new();
    
    [JsonProperty("settings")]
    public Dictionary<string, object> Settings { get; set; } = new();
}

// User Sync Models
public class UserSyncRequest
{
    [JsonProperty("users")]
    public List<ADUser> Users { get; set; } = new();
}

public class ADUser
{
    [JsonProperty("username")]
    public string Username { get; set; } = string.Empty;
    
    [JsonProperty("email")]
    public string Email { get; set; } = string.Empty;
    
    [JsonProperty("first_name")]
    public string FirstName { get; set; } = string.Empty;
    
    [JsonProperty("last_name")]
    public string LastName { get; set; } = string.Empty;
    
    [JsonProperty("display_name")]
    public string DisplayName { get; set; } = string.Empty;
    
    [JsonProperty("ad_object_guid")]
    public string ADObjectGuid { get; set; } = string.Empty;
    
    [JsonProperty("distinguished_name")]
    public string DistinguishedName { get; set; } = string.Empty;
    
    [JsonProperty("is_active")]
    public bool IsActive { get; set; } = true;
    
    [JsonProperty("last_logon")]
    public DateTime? LastLogon { get; set; }
    
    [JsonProperty("password_last_set")]
    public DateTime? PasswordLastSet { get; set; }
    
    [JsonProperty("groups")]
    public List<string> Groups { get; set; } = new();
}

// Group Sync Models
public class GroupSyncRequest
{
    [JsonProperty("groups")]
    public List<ADGroup> Groups { get; set; } = new();
}

public class ADGroup
{
    [JsonProperty("name")]
    public string Name { get; set; } = string.Empty;
    
    [JsonProperty("description")]
    public string Description { get; set; } = string.Empty;
    
    [JsonProperty("ad_object_guid")]
    public string ADObjectGuid { get; set; } = string.Empty;
    
    [JsonProperty("distinguished_name")]
    public string DistinguishedName { get; set; } = string.Empty;
    
    [JsonProperty("group_type")]
    public string GroupType { get; set; } = string.Empty;
    
    [JsonProperty("members")]
    public List<string> Members { get; set; } = new();
}

// Command Models
public class AgentCommand
{
    [JsonProperty("id")]
    public string Id { get; set; } = string.Empty;
    
    [JsonProperty("type")]
    public string Type { get; set; } = string.Empty;
    
    [JsonProperty("action")]
    public string Action { get; set; } = string.Empty;
    
    [JsonProperty("parameters")]
    public Dictionary<string, object> Parameters { get; set; } = new();
    
    [JsonProperty("created_at")]
    public DateTime CreatedAt { get; set; }
    
    [JsonProperty("expires_at")]
    public DateTime? ExpiresAt { get; set; }
}

public class CommandResult
{
    [JsonProperty("command_id")]
    public string CommandId { get; set; } = string.Empty;
    
    [JsonProperty("status")]
    public string Status { get; set; } = string.Empty; // success, error, pending
    
    [JsonProperty("message")]
    public string Message { get; set; } = string.Empty;
    
    [JsonProperty("result_data")]
    public Dictionary<string, object>? ResultData { get; set; }
    
    [JsonProperty("executed_at")]
    public DateTime ExecutedAt { get; set; }
}

// Log Models
public class AgentLogRequest
{
    [JsonProperty("logs")]
    public List<AgentLogEntry> Logs { get; set; } = new();
}

public class AgentLogEntry
{
    [JsonProperty("timestamp")]
    public DateTime Timestamp { get; set; }
    
    [JsonProperty("level")]
    public string Level { get; set; } = string.Empty;
    
    [JsonProperty("message")]
    public string Message { get; set; } = string.Empty;
    
    [JsonProperty("category")]
    public string Category { get; set; } = string.Empty;
    
    [JsonProperty("exception")]
    public string? Exception { get; set; }
    
    [JsonProperty("properties")]
    public Dictionary<string, object>? Properties { get; set; }
}

// Sync Result Models
public class SyncResult
{
    [JsonProperty("success")]
    public bool Success { get; set; }
    
    [JsonProperty("message")]
    public string Message { get; set; } = string.Empty;
    
    [JsonProperty("users_processed")]
    public int UsersProcessed { get; set; }
    
    [JsonProperty("groups_processed")]
    public int GroupsProcessed { get; set; }
    
    [JsonProperty("errors")]
    public List<string> Errors { get; set; } = new();
    
    [JsonProperty("timestamp")]
    public DateTime Timestamp { get; set; }
}