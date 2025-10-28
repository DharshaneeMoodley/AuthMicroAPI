using AuthMicroAPI.Models;
using AuthMicroAPI.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthMicroAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(AuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        // POST: api/auth/login
        [HttpPost("login")]
        public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.UserName) || string.IsNullOrWhiteSpace(request.Password))
                {
                    return BadRequest(new AuthResponse
                    {
                        Success = false,
                        Message = "Username and password are required"
                    });
                }

                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
                var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

                var response = await _authService.LoginAsync(request, ipAddress, userAgent);

                if (!response.Success)
                {
                    return Unauthorized(response);
                }

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login");
                return StatusCode(500, new AuthResponse
                {
                    Success = false,
                    Message = "An error occurred during login"
                });
            }
        }

        // POST: api/auth/validate
        [HttpPost("validate")]
        public async Task<ActionResult<AuthResponse>> ValidateSession([FromBody] ValidateSessionRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.SessionId))
                {
                    return BadRequest(new AuthResponse
                    {
                        Success = false,
                        Message = "Session ID is required"
                    });
                }

                var response = await _authService.ValidateSessionAsync(request.SessionId);

                if (!response.Success)
                {
                    return Unauthorized(response);
                }

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating session");
                return StatusCode(500, new AuthResponse
                {
                    Success = false,
                    Message = "An error occurred during session validation"
                });
            }
        }

        // POST: api/auth/logout
        [HttpPost("logout")]
        public async Task<ActionResult> Logout([FromBody] ValidateSessionRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.SessionId))
                {
                    return BadRequest(new { message = "Session ID is required" });
                }

                var result = await _authService.LogoutAsync(request.SessionId);

                if (result)
                {
                    return Ok(new { message = "Logout successful" });
                }

                return BadRequest(new { message = "Logout failed" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout");
                return StatusCode(500, new { message = "An error occurred during logout" });
            }
        }

        // POST: api/auth/users
        [HttpPost("users")]
        public async Task<ActionResult<AuthResponse>> CreateUser([FromBody] CreateUserRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.UserName) ||
                    string.IsNullOrWhiteSpace(request.Email) ||
                    string.IsNullOrWhiteSpace(request.Password) ||
                    string.IsNullOrWhiteSpace(request.FullName))
                {
                    return BadRequest(new AuthResponse
                    {
                        Success = false,
                        Message = "All fields are required"
                    });
                }

                if (!request.RoleIds.Any())
                {
                    return BadRequest(new AuthResponse
                    {
                        Success = false,
                        Message = "At least one role must be assigned"
                    });
                }

                var response = await _authService.CreateUserAsync(request);

                if (!response.Success)
                {
                    return BadRequest(response);
                }

                return CreatedAtAction(nameof(GetUserById), new { id = response.User?.UserId }, response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating user");
                return StatusCode(500, new AuthResponse
                {
                    Success = false,
                    Message = "An error occurred while creating the user"
                });
            }
        }

        // PUT: api/auth/users/{id}
        [HttpPut("users/{id}")]
        public async Task<ActionResult<AuthResponse>> UpdateUser(int id, [FromBody] UpdateUserRequest request)
        {
            try
            {
                if (id != request.UserId)
                {
                    return BadRequest(new AuthResponse
                    {
                        Success = false,
                        Message = "User ID mismatch"
                    });
                }

                if (string.IsNullOrWhiteSpace(request.UserName) ||
                    string.IsNullOrWhiteSpace(request.Email) ||
                    string.IsNullOrWhiteSpace(request.FullName))
                {
                    return BadRequest(new AuthResponse
                    {
                        Success = false,
                        Message = "All fields are required"
                    });
                }

                var response = await _authService.UpdateUserAsync(request);

                if (!response.Success)
                {
                    return BadRequest(response);
                }

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating user");
                return StatusCode(500, new AuthResponse
                {
                    Success = false,
                    Message = "An error occurred while updating the user"
                });
            }
        }

        // POST: api/auth/change-password
        [HttpPost("change-password")]
        public async Task<ActionResult<AuthResponse>> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.CurrentPassword) ||
                    string.IsNullOrWhiteSpace(request.NewPassword))
                {
                    return BadRequest(new AuthResponse
                    {
                        Success = false,
                        Message = "Current and new passwords are required"
                    });
                }

                if (request.NewPassword.Length < 6)
                {
                    return BadRequest(new AuthResponse
                    {
                        Success = false,
                        Message = "New password must be at least 6 characters long"
                    });
                }

                var response = await _authService.ChangePasswordAsync(request);

                if (!response.Success)
                {
                    return BadRequest(response);
                }

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error changing password");
                return StatusCode(500, new AuthResponse
                {
                    Success = false,
                    Message = "An error occurred while changing the password"
                });
            }
        }

        // GET: api/auth/users
        [HttpGet("users")]
        public async Task<ActionResult<List<UserDto>>> GetAllUsers()
        {
            try
            {
                var users = await _authService.GetAllUsersAsync();
                return Ok(users);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting users");
                return StatusCode(500, new { message = "An error occurred while retrieving users" });
            }
        }

        // GET: api/auth/users/{id}
        [HttpGet("users/{id}")]
        public async Task<ActionResult<UserDto>> GetUserById(int id)
        {
            try
            {
                var user = await _authService.GetUserByIdAsync(id);

                if (user == null)
                {
                    return NotFound(new { message = "User not found" });
                }

                return Ok(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user");
                return StatusCode(500, new { message = "An error occurred while retrieving the user" });
            }
        }

        // GET: api/auth/roles
        [HttpGet("roles")]
        public async Task<ActionResult<List<Role>>> GetAllRoles()
        {
            try
            {
                var roles = await _authService.GetAllRolesAsync();
                return Ok(roles);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting roles");
                return StatusCode(500, new { message = "An error occurred while retrieving roles" });
            }
        }
    }
}