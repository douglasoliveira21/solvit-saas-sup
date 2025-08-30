using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SaasIdentityAgent.Models;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security;

namespace SaasIdentityAgent.Services;

public interface IActiveDirectoryService
{
    Task<List<ADUser>> GetUsersAsync(string? searchFilter = null);
    Task<List<ADGroup>> GetGroupsAsync(string? searchFilter = null);
    Task<bool> CreateUserAsync(string username, string firstName, string lastName, string email, string password, string? organizationalUnit = null);
    Task<bool> AddUserToGroupAsync(string username, string groupName);
    Task<bool> DisableUserAsync(string username);
    Task<bool> EnableUserAsync(string username);
    Task<bool> DeleteUserAsync(string username);
    Task<bool> UpdateUserAsync(string username, Dictionary<string, object> properties);
    Task<bool> CreateGroupAsync(string groupName, string? description = null, string? organizationalUnit = null);
    Task<bool> TestConnectionAsync();
}

public class ActiveDirectoryService : IActiveDirectoryService
{
    private readonly ILogger<ActiveDirectoryService> _logger;
    private readonly ActiveDirectoryConfiguration _config;
    private PrincipalContext? _principalContext;

    public ActiveDirectoryService(
        ILogger<ActiveDirectoryService> logger,
        IOptions<ActiveDirectoryConfiguration> config)
    {
        _logger = logger;
        _config = config.Value;
    }

    private async Task<PrincipalContext> GetPrincipalContextAsync()
    {
        if (_principalContext == null)
        {
            await Task.Run(() =>
            {
                try
                {
                    var contextOptions = ContextOptions.Negotiate;
                    if (_config.UseSecureConnection)
                    {
                        contextOptions |= ContextOptions.SecureSocketLayer;
                    }

                    if (!string.IsNullOrEmpty(_config.ServiceAccountUsername))
                    {
                        _principalContext = new PrincipalContext(
                            ContextType.Domain,
                            _config.DomainName,
                            _config.ServiceAccountUsername,
                            _config.ServiceAccountPassword,
                            contextOptions);
                    }
                    else
                    {
                        _principalContext = new PrincipalContext(
                            ContextType.Domain,
                            _config.DomainName,
                            contextOptions);
                    }

                    _logger.LogInformation("Connected to Active Directory domain: {Domain}", _config.DomainName);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to connect to Active Directory");
                    throw;
                }
            });
        }

        return _principalContext!;
    }

    public async Task<bool> TestConnectionAsync()
    {
        try
        {
            var context = await GetPrincipalContextAsync();
            
            // Try to find a user to test the connection
            using var searcher = new PrincipalSearcher(new UserPrincipal(context));
            var result = searcher.FindOne();
            
            _logger.LogInformation("Active Directory connection test successful");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Active Directory connection test failed");
            return false;
        }
    }

    public async Task<List<ADUser>> GetUsersAsync(string? searchFilter = null)
    {
        var users = new List<ADUser>();
        
        try
        {
            var context = await GetPrincipalContextAsync();
            
            using var userPrincipal = new UserPrincipal(context);
            if (!string.IsNullOrEmpty(searchFilter))
            {
                userPrincipal.Name = $"*{searchFilter}*";
            }
            
            using var searcher = new PrincipalSearcher(userPrincipal);
            
            await Task.Run(() =>
            {
                foreach (UserPrincipal user in searcher.FindAll())
                {
                    try
                    {
                        users.Add(new ADUser
                        {
                            Username = user.SamAccountName ?? string.Empty,
                            FirstName = user.GivenName ?? string.Empty,
                            LastName = user.Surname ?? string.Empty,
                            Email = user.EmailAddress ?? string.Empty,
                            DisplayName = user.DisplayName ?? string.Empty,
                            IsEnabled = user.Enabled ?? false,
                            LastLogon = user.LastLogon,
                            DistinguishedName = user.DistinguishedName ?? string.Empty,
                            Groups = GetUserGroups(user)
                        });
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error processing user {Username}", user.SamAccountName);
                    }
                    finally
                    {
                        user.Dispose();
                    }
                }
            });
            
            _logger.LogInformation("Retrieved {Count} users from Active Directory", users.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving users from Active Directory");
        }
        
        return users;
    }

    public async Task<List<ADGroup>> GetGroupsAsync(string? searchFilter = null)
    {
        var groups = new List<ADGroup>();
        
        try
        {
            var context = await GetPrincipalContextAsync();
            
            using var groupPrincipal = new GroupPrincipal(context);
            if (!string.IsNullOrEmpty(searchFilter))
            {
                groupPrincipal.Name = $"*{searchFilter}*";
            }
            
            using var searcher = new PrincipalSearcher(groupPrincipal);
            
            await Task.Run(() =>
            {
                foreach (GroupPrincipal group in searcher.FindAll())
                {
                    try
                    {
                        groups.Add(new ADGroup
                        {
                            Name = group.SamAccountName ?? string.Empty,
                            DisplayName = group.DisplayName ?? string.Empty,
                            Description = group.Description ?? string.Empty,
                            DistinguishedName = group.DistinguishedName ?? string.Empty,
                            Members = GetGroupMembers(group)
                        });
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error processing group {GroupName}", group.SamAccountName);
                    }
                    finally
                    {
                        group.Dispose();
                    }
                }
            });
            
            _logger.LogInformation("Retrieved {Count} groups from Active Directory", groups.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving groups from Active Directory");
        }
        
        return groups;
    }

    public async Task<bool> CreateUserAsync(string username, string firstName, string lastName, string email, string password, string? organizationalUnit = null)
    {
        try
        {
            var context = await GetPrincipalContextAsync();
            
            // Check if user already exists
            using var existingUser = UserPrincipal.FindByIdentity(context, username);
            if (existingUser != null)
            {
                _logger.LogWarning("User {Username} already exists", username);
                return false;
            }
            
            await Task.Run(() =>
            {
                using var newUser = new UserPrincipal(context)
                {
                    SamAccountName = username,
                    GivenName = firstName,
                    Surname = lastName,
                    EmailAddress = email,
                    DisplayName = $"{firstName} {lastName}",
                    UserPrincipalName = $"{username}@{_config.DomainName}",
                    Enabled = true
                };
                
                newUser.SetPassword(password);
                newUser.Save();
                
                // Move to specific OU if specified
                if (!string.IsNullOrEmpty(organizationalUnit))
                {
                    MoveUserToOU(newUser, organizationalUnit);
                }
            });
            
            _logger.LogInformation("User {Username} created successfully", username);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating user {Username}", username);
            return false;
        }
    }

    public async Task<bool> AddUserToGroupAsync(string username, string groupName)
    {
        try
        {
            var context = await GetPrincipalContextAsync();
            
            await Task.Run(() =>
            {
                using var user = UserPrincipal.FindByIdentity(context, username);
                using var group = GroupPrincipal.FindByIdentity(context, groupName);
                
                if (user == null)
                {
                    _logger.LogWarning("User {Username} not found", username);
                    return;
                }
                
                if (group == null)
                {
                    _logger.LogWarning("Group {GroupName} not found", groupName);
                    return;
                }
                
                if (!group.Members.Contains(user))
                {
                    group.Members.Add(user);
                    group.Save();
                }
            });
            
            _logger.LogInformation("User {Username} added to group {GroupName}", username, groupName);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding user {Username} to group {GroupName}", username, groupName);
            return false;
        }
    }

    public async Task<bool> DisableUserAsync(string username)
    {
        try
        {
            var context = await GetPrincipalContextAsync();
            
            await Task.Run(() =>
            {
                using var user = UserPrincipal.FindByIdentity(context, username);
                if (user == null)
                {
                    _logger.LogWarning("User {Username} not found", username);
                    return;
                }
                
                user.Enabled = false;
                user.Save();
            });
            
            _logger.LogInformation("User {Username} disabled successfully", username);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error disabling user {Username}", username);
            return false;
        }
    }

    public async Task<bool> EnableUserAsync(string username)
    {
        try
        {
            var context = await GetPrincipalContextAsync();
            
            await Task.Run(() =>
            {
                using var user = UserPrincipal.FindByIdentity(context, username);
                if (user == null)
                {
                    _logger.LogWarning("User {Username} not found", username);
                    return;
                }
                
                user.Enabled = true;
                user.Save();
            });
            
            _logger.LogInformation("User {Username} enabled successfully", username);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error enabling user {Username}", username);
            return false;
        }
    }

    public async Task<bool> DeleteUserAsync(string username)
    {
        try
        {
            var context = await GetPrincipalContextAsync();
            
            await Task.Run(() =>
            {
                using var user = UserPrincipal.FindByIdentity(context, username);
                if (user == null)
                {
                    _logger.LogWarning("User {Username} not found", username);
                    return;
                }
                
                user.Delete();
            });
            
            _logger.LogInformation("User {Username} deleted successfully", username);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting user {Username}", username);
            return false;
        }
    }

    public async Task<bool> UpdateUserAsync(string username, Dictionary<string, object> properties)
    {
        try
        {
            var context = await GetPrincipalContextAsync();
            
            await Task.Run(() =>
            {
                using var user = UserPrincipal.FindByIdentity(context, username);
                if (user == null)
                {
                    _logger.LogWarning("User {Username} not found", username);
                    return;
                }
                
                foreach (var property in properties)
                {
                    switch (property.Key.ToLower())
                    {
                        case "firstname":
                        case "givenname":
                            user.GivenName = property.Value?.ToString();
                            break;
                        case "lastname":
                        case "surname":
                            user.Surname = property.Value?.ToString();
                            break;
                        case "email":
                        case "emailaddress":
                            user.EmailAddress = property.Value?.ToString();
                            break;
                        case "displayname":
                            user.DisplayName = property.Value?.ToString();
                            break;
                        case "enabled":
                            if (bool.TryParse(property.Value?.ToString(), out bool enabled))
                            {
                                user.Enabled = enabled;
                            }
                            break;
                    }
                }
                
                user.Save();
            });
            
            _logger.LogInformation("User {Username} updated successfully", username);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating user {Username}", username);
            return false;
        }
    }

    public async Task<bool> CreateGroupAsync(string groupName, string? description = null, string? organizationalUnit = null)
    {
        try
        {
            var context = await GetPrincipalContextAsync();
            
            // Check if group already exists
            using var existingGroup = GroupPrincipal.FindByIdentity(context, groupName);
            if (existingGroup != null)
            {
                _logger.LogWarning("Group {GroupName} already exists", groupName);
                return false;
            }
            
            await Task.Run(() =>
            {
                using var newGroup = new GroupPrincipal(context)
                {
                    SamAccountName = groupName,
                    DisplayName = groupName,
                    Description = description ?? string.Empty
                };
                
                newGroup.Save();
                
                // Move to specific OU if specified
                if (!string.IsNullOrEmpty(organizationalUnit))
                {
                    MoveGroupToOU(newGroup, organizationalUnit);
                }
            });
            
            _logger.LogInformation("Group {GroupName} created successfully", groupName);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating group {GroupName}", groupName);
            return false;
        }
    }

    private List<string> GetUserGroups(UserPrincipal user)
    {
        var groups = new List<string>();
        try
        {
            foreach (Principal group in user.GetGroups())
            {
                groups.Add(group.SamAccountName ?? string.Empty);
                group.Dispose();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error getting groups for user {Username}", user.SamAccountName);
        }
        return groups;
    }

    private List<string> GetGroupMembers(GroupPrincipal group)
    {
        var members = new List<string>();
        try
        {
            foreach (Principal member in group.GetMembers())
            {
                members.Add(member.SamAccountName ?? string.Empty);
                member.Dispose();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error getting members for group {GroupName}", group.SamAccountName);
        }
        return members;
    }

    private void MoveUserToOU(UserPrincipal user, string organizationalUnit)
    {
        try
        {
            using var directoryEntry = user.GetUnderlyingObject() as DirectoryEntry;
            directoryEntry?.MoveTo(new DirectoryEntry($"LDAP://{organizationalUnit}"));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error moving user {Username} to OU {OU}", user.SamAccountName, organizationalUnit);
        }
    }

    private void MoveGroupToOU(GroupPrincipal group, string organizationalUnit)
    {
        try
        {
            using var directoryEntry = group.GetUnderlyingObject() as DirectoryEntry;
            directoryEntry?.MoveTo(new DirectoryEntry($"LDAP://{organizationalUnit}"));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error moving group {GroupName} to OU {OU}", group.SamAccountName, organizationalUnit);
        }
    }

    public void Dispose()
    {
        _principalContext?.Dispose();
    }
}