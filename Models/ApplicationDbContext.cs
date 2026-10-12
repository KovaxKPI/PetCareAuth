using Microsoft.EntityFrameworkCore;
using PetCareAuth.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace PetCareAuth.Models;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
    : IdentityDbContext<ApplicationUser>(options);