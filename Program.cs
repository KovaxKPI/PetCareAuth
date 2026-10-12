using Azure.Identity;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PetCareAuth.Identity;
using PetCareAuth.Models;
using PetCareAuth.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

var keyVaultUrl = builder.Configuration["KeyVault:Url"]
                  ?? throw new InvalidOperationException(
                      "KeyVault:Url is not configured.");

builder.Configuration.AddAzureKeyVault(
    new Uri(keyVaultUrl),
    new DefaultAzureCredential());

builder.Services
    .AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.User.RequireUniqueEmail = true;

        options.Password.RequiredLength = 4;
        options.Password.RequireDigit = true;
        options.Password.RequireUppercase = false;
        options.Password.RequireLowercase = false;
        options.Password.RequireNonAlphanumeric = false;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddControllers();
builder.Services.AddSwaggerGen();
builder.Services.AddScoped<ITokenService, TokenService>();

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme =
            IdentityConstants.ApplicationScheme;

        options.DefaultSignInScheme =
            IdentityConstants.ExternalScheme;
        
        options.DefaultAuthenticateScheme = GoogleDefaults.AuthenticationScheme;
    })
    .AddGoogle(options =>
    {
        options.ClientId =
            builder.Configuration["Google:ClientId"]!;

        options.ClientSecret =
            builder.Configuration["Google:ClientSecret"]!;
        
        options.CallbackPath = "/signin-google";
    });

var app = builder.Build();

app.UseHttpsRedirection();

app.UseAuthentication(); 
app.UseAuthorization(); 

app.MapControllers();
app.MapDefaultControllerRoute();

app.UseSwagger();
app.UseSwaggerUI();
    
app.Run();
