using AuthMicroAPI.Data;
using AuthMicroAPI.Models;
using BCrypt.Net;
using Microsoft.EntityFrameworkCore;

namespace AuthMicroAPI.Services
{
    public class AuthService
    {
        private readonly AuthDbContext _context;

        public AuthService(AuthDbContext context)
        {
            _context = context;
        }

        // Login with session creation
        public async Task<AuthResponse> LoginAsync(LoginRequest request, string? ipAddress = null, string? userAgent = null)
        {
            try
            {
                // Find user by username
                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.UserName == request.UserName && u.IsActive);

                if (user == null)
                {
                    return new AuthResponse
                    {
                        Success = false,
                        Message = "Invalid username or password"
                    };
                }

                // Verify password
                if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
                {
                    return new AuthResponse
                    {
                        Success = false,
                        Message = "Invalid username or password"
                    };
                }

                // Get user roles
                var userRoles = await _context.UserRoles
                    .Include(ur => ur.Role)
                    .Where(ur => ur.UserId == user.UserId)
                    .Select(ur => ur.Role.RoleName)
                    .ToListAsync();

                // Create session
                var sessionId = Guid.NewGuid().ToString();
                var session = new Session
                {
                    SessionId = sessionId,
                    UserId = user.UserId,
                    CreatedDate = DateTime.Now,
                    ExpiryDate = DateTime.Now.AddHours(24),
                    IsActive = true,
                    IPAddress = ipAddress,
                    UserAgent = userAgent
                };

                _context.Sessions.Add(session);
                await _context.SaveChangesAsync();

                return new AuthResponse
                {
                    Success = true,
                    SessionId = sessionId,
                    User = new UserDto
                    {
                        UserId = user.UserId,
                        UserName = user.UserName,
                        Email = user.Email,
                        FullName = user.FullName,
                        IsActive = user.IsActive,
                        CreatedDate = user.CreatedDate,
                        Roles = userRoles
                    },
                    Message = "Login successful"
                };
            }
            catch (Exception ex)
            {
                return new AuthResponse
                {
                    Success = false,
                    Message = $"Login error: {ex.Message}"
                };
            }
        }

        // Validate session
        public async Task<AuthResponse> ValidateSessionAsync(string sessionId)
        {
            try
            {
                var session = await _context.Sessions
                    .Include(s => s.User)
                    .FirstOrDefaultAsync(s => s.SessionId == sessionId && s.IsActive);

                if (session == null || session.ExpiryDate < DateTime.Now)
                {
                    return new AuthResponse
                    {
                        Success = false,
                        Message = "Invalid or expired session"
                    };
                }

                // Get user roles
                var userRoles = await _context.UserRoles
                    .Include(ur => ur.Role)
                    .Where(ur => ur.UserId == session.UserId)
                    .Select(ur => ur.Role.RoleName)
                    .ToListAsync();

                return new AuthResponse
                {
                    Success = true,
                    SessionId = sessionId,
                    User = new UserDto
                    {
                        UserId = session.User.UserId,
                        UserName = session.User.UserName,
                        Email = session.User.Email,
                        FullName = session.User.FullName,
                        IsActive = session.User.IsActive,
                        CreatedDate = session.User.CreatedDate,
                        Roles = userRoles
                    },
                    Message = "Session valid"
                };
            }
            catch (Exception ex)
            {
                return new AuthResponse
                {
                    Success = false,
                    Message = $"Validation error: {ex.Message}"
                };
            }
        }

        // Logout
        public async Task<bool> LogoutAsync(string sessionId)
        {
            try
            {
                var session = await _context.Sessions
                    .FirstOrDefaultAsync(s => s.SessionId == sessionId);

                if (session != null)
                {
                    session.IsActive = false;
                    await _context.SaveChangesAsync();
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        // Create new user (admin only)
        public async Task<AuthResponse> CreateUserAsync(CreateUserRequest request)
        {
            try
            {
                // Check if username or email already exists
                var existingUser = await _context.Users
                    .FirstOrDefaultAsync(u => u.UserName == request.UserName || u.Email == request.Email);

                if (existingUser != null)
                {
                    return new AuthResponse
                    {
                        Success = false,
                        Message = "Username or email already exists"
                    };
                }

                // Validate roles
                var validRoles = await _context.Roles
                    .Where(r => request.RoleIds.Contains(r.RoleId))
                    .ToListAsync();

                if (validRoles.Count != request.RoleIds.Count)
                {
                    return new AuthResponse
                    {
                        Success = false,
                        Message = "One or more invalid role IDs"
                    };
                }

                // Create user
                var user = new User
                {
                    UserName = request.UserName,
                    Email = request.Email,
                    FullName = request.FullName,
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
                    IsActive = true,
                    CreatedDate = DateTime.Now
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                // Assign roles
                foreach (var roleId in request.RoleIds)
                {
                    _context.UserRoles.Add(new UserRole
                    {
                        UserId = user.UserId,
                        RoleId = roleId
                    });
                }

                await _context.SaveChangesAsync();

                var roleNames = validRoles.Select(r => r.RoleName).ToList();

                return new AuthResponse
                {
                    Success = true,
                    User = new UserDto
                    {
                        UserId = user.UserId,
                        UserName = user.UserName,
                        Email = user.Email,
                        FullName = user.FullName,
                        IsActive = user.IsActive,
                        CreatedDate = user.CreatedDate,
                        Roles = roleNames
                    },
                    Message = "User created successfully"
                };
            }
            catch (Exception ex)
            {
                return new AuthResponse
                {
                    Success = false,
                    Message = $"Error creating user: {ex.Message}"
                };
            }
        }

        // Update user
        public async Task<AuthResponse> UpdateUserAsync(UpdateUserRequest request)
        {
            try
            {
                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.UserId == request.UserId);

                if (user == null)
                {
                    return new AuthResponse
                    {
                        Success = false,
                        Message = "User not found"
                    };
                }

                // Check if new username/email conflicts with another user
                var conflict = await _context.Users
                    .FirstOrDefaultAsync(u => u.UserId != request.UserId &&
                                            (u.UserName == request.UserName || u.Email == request.Email));

                if (conflict != null)
                {
                    return new AuthResponse
                    {
                        Success = false,
                        Message = "Username or email already in use"
                    };
                }

                // Update user properties
                user.UserName = request.UserName;
                user.Email = request.Email;
                user.FullName = request.FullName;
                user.IsActive = request.IsActive;

                // Update roles if provided
                if (request.RoleIds.Any())
                {
                    // Remove existing roles
                    var existingRoles = await _context.UserRoles
                        .Where(ur => ur.UserId == user.UserId)
                        .ToListAsync();
                    _context.UserRoles.RemoveRange(existingRoles);

                    // Add new roles
                    foreach (var roleId in request.RoleIds)
                    {
                        _context.UserRoles.Add(new UserRole
                        {
                            UserId = user.UserId,
                            RoleId = roleId
                        });
                    }
                }

                await _context.SaveChangesAsync();

                // Get updated roles
                var userRoles = await _context.UserRoles
                    .Include(ur => ur.Role)
                    .Where(ur => ur.UserId == user.UserId)
                    .Select(ur => ur.Role.RoleName)
                    .ToListAsync();

                return new AuthResponse
                {
                    Success = true,
                    User = new UserDto
                    {
                        UserId = user.UserId,
                        UserName = user.UserName,
                        Email = user.Email,
                        FullName = user.FullName,
                        IsActive = user.IsActive,
                        CreatedDate = user.CreatedDate,
                        Roles = userRoles
                    },
                    Message = "User updated successfully"
                };
            }
            catch (Exception ex)
            {
                return new AuthResponse
                {
                    Success = false,
                    Message = $"Error updating user: {ex.Message}"
                };
            }
        }

        // Change password
        public async Task<AuthResponse> ChangePasswordAsync(ChangePasswordRequest request)
        {
            try
            {
                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.UserId == request.UserId);

                if (user == null)
                {
                    return new AuthResponse
                    {
                        Success = false,
                        Message = "User not found"
                    };
                }

                // Verify current password
                if (!BCrypt.Net.BCrypt.Verify(request.CurrentPassword, user.PasswordHash))
                {
                    return new AuthResponse
                    {
                        Success = false,
                        Message = "Current password is incorrect"
                    };
                }

                // Update password
                user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
                await _context.SaveChangesAsync();

                return new AuthResponse
                {
                    Success = true,
                    Message = "Password changed successfully"
                };
            }
            catch (Exception ex)
            {
                return new AuthResponse
                {
                    Success = false,
                    Message = $"Error changing password: {ex.Message}"
                };
            }
        }

        // Get all users (admin only)
        public async Task<List<UserDto>> GetAllUsersAsync()
        {
            var users = await _context.Users
                .Select(u => new UserDto
                {
                    UserId = u.UserId,
                    UserName = u.UserName,
                    Email = u.Email,
                    FullName = u.FullName,
                    IsActive = u.IsActive,
                    CreatedDate = u.CreatedDate,
                    Roles = _context.UserRoles
                        .Where(ur => ur.UserId == u.UserId)
                        .Select(ur => ur.Role.RoleName)
                        .ToList()
                })
                .ToListAsync();

            return users;
        }

        // Get user by ID
        public async Task<UserDto?> GetUserByIdAsync(int userId)
        {
            var user = await _context.Users
                .Where(u => u.UserId == userId)
                .Select(u => new UserDto
                {
                    UserId = u.UserId,
                    UserName = u.UserName,
                    Email = u.Email,
                    FullName = u.FullName,
                    IsActive = u.IsActive,
                    CreatedDate = u.CreatedDate,
                    Roles = _context.UserRoles
                        .Where(ur => ur.UserId == u.UserId)
                        .Select(ur => ur.Role.RoleName)
                        .ToList()
                })
                .FirstOrDefaultAsync();

            return user;
        }

        // Get all roles
        public async Task<List<Role>> GetAllRolesAsync()
        {
            return await _context.Roles.ToListAsync();
        }
    }
}