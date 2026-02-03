using SafeVault.Data;
using SafeVault.Services;
using SafeVault.Models;
using Microsoft.EntityFrameworkCore;

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

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

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
        Email = System.Web.HttpUtility.HtmlEncode(u.Email)
    });

    return Results.Ok(encodedUsers);
})
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
            email = System.Web.HttpUtility.HtmlEncode(user.Email)
        });
    }
    catch
    {
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
})
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
            Email = System.Web.HttpUtility.HtmlEncode(u.Email)
        });

        return Results.Ok(encodedUsers);
    }
    catch
    {
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
})
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
            Email = System.Web.HttpUtility.HtmlEncode(u.Email)
        });

        return Results.Ok(encodedUsers);
    }
    catch
    {
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
})
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
                email = System.Web.HttpUtility.HtmlEncode(user.Email)
            }
        });
    }
    catch
    {
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
})
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
.WithName("DeleteUser")
.WithOpenApi();

app.Run();
