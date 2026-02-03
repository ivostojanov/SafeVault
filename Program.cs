using SafeVault.Data;
using SafeVault.Services;
using SafeVault.Models;
using SafeVault.Models.DTOs;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add DbContext with SQLite
builder.Services.AddDbContext<SafeVaultContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection") 
        ?? "Data Source=safevault.db"));

// Add input validation service
builder.Services.AddScoped<IInputValidationService, InputValidationService>();

// Add authentication services
builder.Services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();
builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();

// Configure JWT Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["JwtSettings:Issuer"],
            ValidAudience = builder.Configuration["JwtSettings:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["JwtSettings:SecretKey"] 
                    ?? throw new InvalidOperationException("JWT SecretKey not configured"))),
            ClockSkew = TimeSpan.Zero // No tolerance for expiration
        };
    });

// Configure Authorization Policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserOrAdmin", policy => policy.RequireRole("User", "Admin"));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Add security headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Add("Strict-Transport-Security", "max-age=31536000");
    await next();
});

// Authentication and Authorization middleware
app.UseAuthentication();
app.UseAuthorization();

// ============ AUTHENTICATION ENDPOINTS ============

// POST /register - User registration
app.MapPost("/register", async (RegisterRequest request, IAuthenticationService authService) =>
{
    if (request == null)
    {
        return Results.BadRequest(new { success = false, error = "Invalid request" });
    }

    var (success, message, user) = await authService.RegisterUser(
        request.Username,
        request.Email,
        request.Password,
        "User" // Default role for registration
    );

    if (!success)
    {
        return Results.BadRequest(new { success = false, error = message });
    }

    return Results.Ok(new
    {
        success = true,
        message = message,
        user = new
        {
            userId = user!.UserID,
            username = System.Web.HttpUtility.HtmlEncode(user.Username),
            email = System.Web.HttpUtility.HtmlEncode(user.Email),
            role = user.Role,
            createdAt = user.CreatedAt
        }
    });
})
.WithName("Register")
.WithOpenApi();

// POST /login - User authentication
app.MapPost("/login", async (LoginRequest request, IAuthenticationService authService) =>
{
    if (request == null)
    {
        return Results.BadRequest(new { success = false, error = "Invalid request" });
    }

    var response = await authService.AuthenticateUser(request.Username, request.Password);

    if (!response.Success)
    {
        return Results.Unauthorized();
    }

    return Results.Ok(new
    {
        success = response.Success,
        message = response.Message,
        token = response.Token,
        user = response.User
    });
})
.WithName("Login")
.WithOpenApi();

// ============ PROTECTED ENDPOINTS ============

// GET /admin/dashboard - Admin Dashboard (Admin-only access)
app.MapGet("/admin/dashboard", async (SafeVaultContext db) =>
{
    // Gather statistics for admin dashboard
    var totalUsers = await db.Users.CountAsync();
    var activeUsers = await db.Users.CountAsync(u => u.IsActive);
    var inactiveUsers = totalUsers - activeUsers;
    var adminCount = await db.Users.CountAsync(u => u.Role == "Admin");
    var regularUserCount = await db.Users.CountAsync(u => u.Role == "User");
    
    // Recent registrations (last 30 days)
    var thirtyDaysAgo = DateTime.UtcNow.AddDays(-30);
    var recentRegistrations = await db.Users
        .Where(u => u.CreatedAt >= thirtyDaysAgo)
        .CountAsync();
    
    // Users who logged in recently (last 7 days)
    var sevenDaysAgo = DateTime.UtcNow.AddDays(-7);
    var activeInLastWeek = await db.Users
        .Where(u => u.LastLoginAt >= sevenDaysAgo)
        .CountAsync();
    
    // List of all users with their details (admin view)
    var usersList = await db.Users
        .OrderByDescending(u => u.CreatedAt)
        .Select(u => new
        {
            u.UserID,
            Username = System.Web.HttpUtility.HtmlEncode(u.Username),
            Email = System.Web.HttpUtility.HtmlEncode(u.Email),
            u.Role,
            u.IsActive,
            u.CreatedAt,
            u.LastLoginAt
        })
        .ToListAsync();

    return Results.Ok(new
    {
        success = true,
        message = "Admin dashboard data retrieved successfully",
        statistics = new
        {
            totalUsers,
            activeUsers,
            inactiveUsers,
            adminCount,
            regularUserCount,
            recentRegistrations = new
            {
                count = recentRegistrations,
                period = "Last 30 days"
            },
            recentActivity = new
            {
                count = activeInLastWeek,
                period = "Last 7 days"
            }
        },
        users = usersList
    });
})
.RequireAuthorization("AdminOnly")
.WithName("AdminDashboard")
.WithOpenApi()
.WithTags("Admin");

// POST /admin/users/{userId}/activate - Activate user account (Admin-only)
app.MapPost("/admin/users/{userId}/activate", async (int userId, SafeVaultContext db) =>
{
    if (userId <= 0)
    {
        return Results.BadRequest(new { success = false, error = "Invalid user ID" });
    }

    try
    {
        var user = await db.Users.Where(u => u.UserID == userId).FirstOrDefaultAsync();

        if (user == null)
        {
            return Results.NotFound(new { success = false, error = "User not found" });
        }

        user.IsActive = true;
        await db.SaveChangesAsync();

        return Results.Ok(new
        {
            success = true,
            message = $"User '{user.Username}' has been activated",
            user = new
            {
                user.UserID,
                Username = System.Web.HttpUtility.HtmlEncode(user.Username),
                user.IsActive
            }
        });
    }
    catch
    {
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
})
.RequireAuthorization("AdminOnly")
.WithName("ActivateUser")
.WithOpenApi()
.WithTags("Admin");

// POST /admin/users/{userId}/deactivate - Deactivate user account (Admin-only)
app.MapPost("/admin/users/{userId}/deactivate", async (int userId, SafeVaultContext db) =>
{
    if (userId <= 0)
    {
        return Results.BadRequest(new { success = false, error = "Invalid user ID" });
    }

    try
    {
        var user = await db.Users.Where(u => u.UserID == userId).FirstOrDefaultAsync();

        if (user == null)
        {
            return Results.NotFound(new { success = false, error = "User not found" });
        }

        // Prevent deactivating the last admin
        if (user.Role == "Admin")
        {
            var adminCount = await db.Users.CountAsync(u => u.Role == "Admin" && u.IsActive);
            if (adminCount <= 1)
            {
                return Results.BadRequest(new 
                { 
                    success = false, 
                    error = "Cannot deactivate the last active admin account" 
                });
            }
        }

        user.IsActive = false;
        await db.SaveChangesAsync();

        return Results.Ok(new
        {
            success = true,
            message = $"User '{user.Username}' has been deactivated",
            user = new
            {
                user.UserID,
                Username = System.Web.HttpUtility.HtmlEncode(user.Username),
                user.IsActive
            }
        });
    }
    catch
    {
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
})
.RequireAuthorization("AdminOnly")
.WithName("DeactivateUser")
.WithOpenApi()
.WithTags("Admin");

// POST /admin/users/{userId}/promote - Promote user to admin (Admin-only)
app.MapPost("/admin/users/{userId}/promote", async (int userId, SafeVaultContext db) =>
{
    if (userId <= 0)
    {
        return Results.BadRequest(new { success = false, error = "Invalid user ID" });
    }

    try
    {
        var user = await db.Users.Where(u => u.UserID == userId).FirstOrDefaultAsync();

        if (user == null)
        {
            return Results.NotFound(new { success = false, error = "User not found" });
        }

        if (user.Role == "Admin")
        {
            return Results.BadRequest(new 
            { 
                success = false, 
                error = "User is already an admin" 
            });
        }

        user.Role = "Admin";
        await db.SaveChangesAsync();

        return Results.Ok(new
        {
            success = true,
            message = $"User '{user.Username}' has been promoted to Admin",
            user = new
            {
                user.UserID,
                Username = System.Web.HttpUtility.HtmlEncode(user.Username),
                user.Role
            }
        });
    }
    catch
    {
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
})
.RequireAuthorization("AdminOnly")
.WithName("PromoteToAdmin")
.WithOpenApi()
.WithTags("Admin");

// POST endpoint for form submission with secure input validation
app.MapPost("/submit", async (HttpContext context, SafeVaultContext db, IInputValidationService validator) =>
{
    var form = await context.Request.ReadFormAsync();
    var username = form["username"].ToString();
    var email = form["email"].ToString();

    // Validate inputs to prevent SQL injection and XSS
    var validationResult = validator.ValidateUser(username, email);
    
    if (!validationResult.IsValid)
    {
        return Results.BadRequest(new 
        { 
            success = false, 
            errors = validationResult.Errors 
        });
    }

    try
    {
        // Use parameterized queries via Entity Framework (automatic protection against SQL injection)
        var user = new User 
        { 
            Username = username, 
            Email = email 
        };

        db.Users.Add(user);
        await db.SaveChangesAsync();

        return Results.Ok(new 
        { 
            success = true, 
            message = "User registered successfully",
            userId = user.UserID
        });
    }
    catch
    {
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
})
.WithName("SubmitForm")
.WithOpenApi();

// GET endpoint to retrieve users (with HTML encoding for XSS protection)
app.MapGet("/users", async (SafeVaultContext db) =>
{
    var users = await db.Users.ToListAsync();
    
    // Return data with HTML encoding to prevent XSS in responses
    var encodedUsers = users.Select(u => new
    {
        u.UserID,
        Username = System.Web.HttpUtility.HtmlEncode(u.Username),
        Email = System.Web.HttpUtility.HtmlEncode(u.Email),
        Role = u.Role,
        IsActive = u.IsActive
    });

    return Results.Ok(encodedUsers);
})
.RequireAuthorization("UserOrAdmin")
.WithName("GetUsers")
.WithOpenApi();

// GET endpoint to retrieve a user by ID using parameterized query
// EF Core automatically generates: SELECT * FROM Users WHERE UserID = @p0
app.MapGet("/user-by-id", async (int userId, SafeVaultContext db) =>
{
    if (userId <= 0)
    {
        return Results.BadRequest(new { success = false, error = "Invalid user ID" });
    }

    try
    {
        // Parameterized query - EF Core generates SQL with @p0 parameter binding
        var user = await db.Users.Where(u => u.UserID == userId).FirstOrDefaultAsync();

        if (user == null)
        {
            return Results.NotFound(new { success = false, error = "User not found" });
        }

        return Results.Ok(new
        {
            userID = user.UserID,
            username = System.Web.HttpUtility.HtmlEncode(user.Username),
            email = System.Web.HttpUtility.HtmlEncode(user.Email),
            role = user.Role,
            isActive = user.IsActive
        });
    }
    catch
    {
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
})
.RequireAuthorization("UserOrAdmin")
.WithName("GetUserById")
.WithOpenApi();

// GET endpoint to search users by username using parameterized query
// EF Core automatically generates: SELECT * FROM Users WHERE Username = @p0
app.MapGet("/search-user", async (string username, SafeVaultContext db, IInputValidationService validator) =>
{
    if (string.IsNullOrWhiteSpace(username))
    {
        return Results.BadRequest(new { success = false, error = "Username is required" });
    }

    // Validate input to prevent injection attempts
    if (!validator.IsValidUsername(username))
    {
        return Results.BadRequest(new { success = false, error = "Invalid username format" });
    }

    try
    {
        // Parameterized query - EF Core generates SQL with @p0 parameter binding
        var users = await db.Users.Where(u => u.Username == username).ToListAsync();

        if (users.Count == 0)
        {
            return Results.NotFound(new { success = false, error = "No users found" });
        }

        var encodedUsers = users.Select(u => new
        {
            u.UserID,
            Username = System.Web.HttpUtility.HtmlEncode(u.Username),
            Email = System.Web.HttpUtility.HtmlEncode(u.Email),
            Role = u.Role,
            IsActive = u.IsActive
        });

        return Results.Ok(encodedUsers);
    }
    catch
    {
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
})
.RequireAuthorization("UserOrAdmin")
.WithName("SearchUser")
.WithOpenApi();

// GET endpoint to search users by email using parameterized query
// EF Core automatically generates: SELECT * FROM Users WHERE Email = @p0
app.MapGet("/search-email", async (string email, SafeVaultContext db, IInputValidationService validator) =>
{
    if (string.IsNullOrWhiteSpace(email))
    {
        return Results.BadRequest(new { success = false, error = "Email is required" });
    }

    // Validate input to prevent injection attempts
    if (!validator.IsValidEmail(email))
    {
        return Results.BadRequest(new { success = false, error = "Invalid email format" });
    }

    try
    {
        // Parameterized query - EF Core generates SQL with @p0 parameter binding
        var users = await db.Users.Where(u => u.Email == email).ToListAsync();

        if (users.Count == 0)
        {
            return Results.NotFound(new { success = false, error = "No users found" });
        }

        var encodedUsers = users.Select(u => new
        {
            u.UserID,
            Username = System.Web.HttpUtility.HtmlEncode(u.Username),
            Email = System.Web.HttpUtility.HtmlEncode(u.Email),
            Role = u.Role,
            IsActive = u.IsActive
        });

        return Results.Ok(encodedUsers);
    }
    catch
    {
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
})
.RequireAuthorization("UserOrAdmin")
.WithName("SearchEmail")
.WithOpenApi();

// POST endpoint to update user by ID using parameterized query
// EF Core automatically generates: UPDATE Users SET Username = @p0, Email = @p1 WHERE UserID = @p2
app.MapPost("/update-user/{userId}", async (int userId, HttpContext context, SafeVaultContext db, IInputValidationService validator) =>
{
    if (userId <= 0)
    {
        return Results.BadRequest(new { success = false, error = "Invalid user ID" });
    }

    try
    {
        var form = await context.Request.ReadFormAsync();
        var newUsername = form["username"].ToString();
        var newEmail = form["email"].ToString();

        // Validate inputs
        var validationResult = validator.ValidateUser(newUsername, newEmail);
        if (!validationResult.IsValid)
        {
            return Results.BadRequest(new 
            { 
                success = false, 
                errors = validationResult.Errors 
            });
        }

        // Parameterized query - EF Core handles parameter binding automatically
        var user = await db.Users.Where(u => u.UserID == userId).FirstOrDefaultAsync();

        if (user == null)
        {
            return Results.NotFound(new { success = false, error = "User not found" });
        }

        user.Username = newUsername;
        user.Email = newEmail;

        // SaveChangesAsync generates UPDATE with @p0, @p1, @p2 parameter binding
        await db.SaveChangesAsync();

        return Results.Ok(new 
        { 
            success = true, 
            message = "User updated successfully",
            user = new
            {
                userID = user.UserID,
                username = System.Web.HttpUtility.HtmlEncode(user.Username),
                email = System.Web.HttpUtility.HtmlEncode(user.Email),
                role = user.Role
            }
        });
    }
    catch
    {
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
})
.RequireAuthorization("AdminOnly")
.WithName("UpdateUser")
.WithOpenApi();

// POST endpoint to delete user by ID using parameterized query
// EF Core automatically generates: DELETE FROM Users WHERE UserID = @p0
app.MapPost("/delete-user/{userId}", async (int userId, SafeVaultContext db) =>
{
    if (userId <= 0)
    {
        return Results.BadRequest(new { success = false, error = "Invalid user ID" });
    }

    try
    {
        // Parameterized query - EF Core handles parameter binding automatically
        var user = await db.Users.Where(u => u.UserID == userId).FirstOrDefaultAsync();

        if (user == null)
        {
            return Results.NotFound(new { success = false, error = "User not found" });
        }

        db.Users.Remove(user);

        // SaveChangesAsync generates DELETE with @p0 parameter binding
        await db.SaveChangesAsync();

        return Results.Ok(new 
        { 
            success = true, 
            message = "User deleted successfully",
            deletedUserId = userId
        });
    }
    catch
    {
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
})
.RequireAuthorization("AdminOnly")
.WithName("DeleteUser")
.WithOpenApi();

// ============ VULNERABLE ENDPOINTS (FOR EDUCATIONAL DEMONSTRATION) ============
// WARNING: These endpoints contain INTENTIONAL security vulnerabilities
// They demonstrate what NOT to do in production code
// FOR LEARNING PURPOSES ONLY - DO NOT USE IN PRODUCTION

// Vulnerable Endpoint 1: SQL Injection via String Concatenation
app.MapGet("/vulnerable/search-user", async (string username, SafeVaultContext db) =>
{
    try
    {
        // VULNERABILITY: String concatenation creates SQL injection risk
        // This allows attackers to inject malicious SQL code
        var sqlQuery = $"SELECT * FROM Users WHERE Username = '{username}'";
        
        // DANGER: Executing raw SQL with user input
        var users = await db.Users
            .FromSqlRaw(sqlQuery)
            .ToListAsync();
        
        // VULNERABILITY: No output encoding
        return Results.Ok(users);
    }
    catch (Exception ex)
    {
        // VULNERABILITY: Exposing error details
        return Results.BadRequest(new { error = ex.Message });
    }
})
.WithName("VulnerableSearchUser")
.WithTags("Vulnerable")
.WithOpenApi();

// Vulnerable Endpoint 2: XSS via Missing Output Encoding
app.MapPost("/vulnerable/submit-comment", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    var comment = form["comment"].ToString();
    
    // VULNERABILITY: No input validation or sanitization
    // VULNERABILITY: No output encoding - XSS risk
    
    return Results.Ok(new
    {
        success = true,
        // Raw output without encoding - allows script injection
        message = $"Comment received: {comment}",
        timestamp = DateTime.UtcNow
    });
})
.WithName("VulnerableSubmitComment")
.WithTags("Vulnerable")
.WithOpenApi();

// Vulnerable Endpoint 3: XSS in HTML Response
app.MapGet("/vulnerable/display-user/{userId}", async (int userId, SafeVaultContext db) =>
{
    var user = await db.Users.FindAsync(userId);
    
    if (user == null)
    {
        return Results.NotFound(new { error = "User not found" });
    }
    
    // VULNERABILITY: No HTML encoding on output - XSS risk
    // Any malicious content in username/email will be executed
    return Results.Content($@"
        <!DOCTYPE html>
        <html>
        <head>
            <title>User Profile</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .profile {{ border: 1px solid #ccc; padding: 20px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class='profile'>
                <h1>User Profile</h1>
                <p><strong>User ID:</strong> {user.UserID}</p>
                <p><strong>Username:</strong> {user.Username}</p>
                <p><strong>Email:</strong> {user.Email}</p>
                <p><strong>Role:</strong> {user.Role}</p>
            </div>
        </body>
        </html>
    ", "text/html");
})
.WithName("VulnerableDisplayUser")
.WithTags("Vulnerable")
.WithOpenApi();

// Vulnerable Endpoint 4: SQL Injection in Search by Email
app.MapGet("/vulnerable/search-email", async (string email, SafeVaultContext db) =>
{
    try
    {
        // VULNERABILITY: String interpolation in SQL query
        var sqlQuery = $"SELECT * FROM Users WHERE Email = '{email}'";
        
        var users = await db.Users
            .FromSqlRaw(sqlQuery)
            .ToListAsync();
        
        return Results.Ok(users);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
})
.WithName("VulnerableSearchEmail")
.WithTags("Vulnerable")
.WithOpenApi();

// ============ SECURE FIXED ENDPOINTS (PROPER IMPLEMENTATION) ============
// These endpoints demonstrate the correct way to handle security
// They show the fixes applied to prevent SQL injection and XSS attacks

// Secure Endpoint 1: Search User with Parameterized Query
app.MapGet("/secure/search-user", async (string username, SafeVaultContext db, IInputValidationService validator) =>
{
    // FIX 1: Input validation
    if (!validator.IsValidUsername(username))
    {
        return Results.BadRequest(new { 
            success = false, 
            error = "Invalid username format" 
        });
    }

    try
    {
        // FIX 2: Parameterized query (EF Core handles this automatically)
        // No string concatenation - parameters are passed separately
        var users = await db.Users
            .Where(u => u.Username == username)
            .Select(u => new
            {
                u.UserID,
                // FIX 3: Output encoding
                Username = System.Web.HttpUtility.HtmlEncode(u.Username),
                Email = System.Web.HttpUtility.HtmlEncode(u.Email),
                u.Role,
                u.IsActive
            })
            .ToListAsync();

        if (users.Count == 0)
        {
            return Results.NotFound(new { 
                success = false, 
                message = "No users found" 
            });
        }

        return Results.Ok(new { 
            success = true, 
            count = users.Count, 
            users 
        });
    }
    catch
    {
        // FIX 4: Generic error message (no information disclosure)
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
})
.WithName("SecureSearchUser")
.WithTags("Secure")
.WithOpenApi();

// Secure Endpoint 2: Submit Comment with Validation and Encoding
app.MapPost("/secure/submit-comment", async (HttpContext context, IInputValidationService validator) =>
{
    var form = await context.Request.ReadFormAsync();
    var comment = form["comment"].ToString();

    // FIX 1: Input validation
    var validationResult = validator.ValidateComment(comment);
    if (!validationResult.IsValid)
    {
        return Results.BadRequest(new
        {
            success = false,
            errors = validationResult.Errors
        });
    }

    // FIX 2: Output encoding
    var encodedComment = System.Web.HttpUtility.HtmlEncode(comment);

    return Results.Ok(new
    {
        success = true,
        message = $"Comment received: {encodedComment}",
        timestamp = DateTime.UtcNow,
        note = "Comment has been validated and encoded for security"
    });
})
.WithName("SecureSubmitComment")
.WithTags("Secure")
.WithOpenApi();

// Secure Endpoint 3: Display User with HTML Encoding
app.MapGet("/secure/display-user/{userId}", async (int userId, SafeVaultContext db) =>
{
    if (userId <= 0)
    {
        return Results.BadRequest(new { error = "Invalid user ID" });
    }

    var user = await db.Users.FindAsync(userId);

    if (user == null)
    {
        return Results.NotFound(new { error = "User not found" });
    }

    // FIX: HTML encoding on all output
    var encodedUsername = System.Web.HttpUtility.HtmlEncode(user.Username);
    var encodedEmail = System.Web.HttpUtility.HtmlEncode(user.Email);
    var encodedRole = System.Web.HttpUtility.HtmlEncode(user.Role);

    return Results.Content($@"
        <!DOCTYPE html>
        <html>
        <head>
            <title>User Profile (Secure)</title>
            <style>
                body {{ 
                    font-family: Arial, sans-serif; 
                    margin: 20px; 
                    background-color: #f5f5f5;
                }}
                .profile {{ 
                    background-color: white;
                    border: 1px solid #ddd; 
                    padding: 20px; 
                    border-radius: 5px;
                    max-width: 600px;
                    margin: 0 auto;
                }}
                .security-badge {{
                    background-color: #4CAF50;
                    color: white;
                    padding: 5px 10px;
                    border-radius: 3px;
                    font-size: 12px;
                    display: inline-block;
                    margin-bottom: 10px;
                }}
                h1 {{ color: #333; }}
                .field {{ margin: 10px 0; }}
                .label {{ font-weight: bold; color: #666; }}
            </style>
        </head>
        <body>
            <div class='profile'>
                <span class='security-badge'>🔒 Secured with HTML Encoding</span>
                <h1>User Profile</h1>
                <div class='field'>
                    <span class='label'>User ID:</span> {user.UserID}
                </div>
                <div class='field'>
                    <span class='label'>Username:</span> {encodedUsername}
                </div>
                <div class='field'>
                    <span class='label'>Email:</span> {encodedEmail}
                </div>
                <div class='field'>
                    <span class='label'>Role:</span> {encodedRole}
                </div>
                <div class='field'>
                    <span class='label'>Status:</span> {(user.IsActive ? "Active" : "Inactive")}
                </div>
            </div>
        </body>
        </html>
    ", "text/html");
})
.WithName("SecureDisplayUser")
.WithTags("Secure")
.WithOpenApi();

// Secure Endpoint 4: Search by Email with Validation
app.MapGet("/secure/search-email", async (string email, SafeVaultContext db, IInputValidationService validator) =>
{
    // FIX 1: Input validation
    if (!validator.IsValidEmail(email))
    {
        return Results.BadRequest(new { 
            success = false, 
            error = "Invalid email format" 
        });
    }

    try
    {
        // FIX 2: Parameterized query via LINQ
        var users = await db.Users
            .Where(u => u.Email == email)
            .Select(u => new
            {
                u.UserID,
                // FIX 3: Output encoding
                Username = System.Web.HttpUtility.HtmlEncode(u.Username),
                Email = System.Web.HttpUtility.HtmlEncode(u.Email),
                u.Role,
                u.IsActive
            })
            .ToListAsync();

        if (users.Count == 0)
        {
            return Results.NotFound(new { 
                success = false, 
                message = "No users found" 
            });
        }

        return Results.Ok(new { 
            success = true, 
            count = users.Count, 
            users 
        });
    }
    catch
    {
        // FIX 4: Generic error message
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
})
.WithName("SecureSearchEmail")
.WithTags("Secure")
.WithOpenApi();

app.Run();
