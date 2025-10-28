namespace AuthMicroAPI.Models
{
    // Login Request
    public class LoginRequest
    {
        public string UserName { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    // Create User Request
    public class CreateUserRequest
    {
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public List<int> RoleIds { get; set; } = new();
    }

    // Update User Request
    public class UpdateUserRequest
    {
        public int UserId { get; set; }
        public string UserName { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public List<int> RoleIds { get; set; } = new();
    }

    // Auth Response
    public class AuthResponse
    {
        public bool Success { get; set; }
        public UserDto? User { get; set; }
        public string? SessionId { get; set; }
        public string? Message { get; set; }
    }

    // User DTO
    public class UserDto
    {
        public int UserId { get; set; }
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public DateTime CreatedDate { get; set; }
        public List<string> Roles { get; set; } = new();
    }

    // Validate Session Request
    public class ValidateSessionRequest
    {
        public string SessionId { get; set; } = string.Empty;
    }

    // Change Password Request
    public class ChangePasswordRequest
    {
        public int UserId { get; set; }
        public string CurrentPassword { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }
}