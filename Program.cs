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

app.Run();
