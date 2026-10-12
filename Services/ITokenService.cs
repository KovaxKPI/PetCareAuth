using PetCareAuth.Identity;

namespace PetCareAuth.Services;

public interface ITokenService
{
    string GenerateToken(ApplicationUser user, IList<string> roles);
}