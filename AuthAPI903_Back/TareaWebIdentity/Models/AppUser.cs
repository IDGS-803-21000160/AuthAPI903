using Microsoft.AspNetCore.Identity;

namespace TareaWebIdentity.Models
{
    public class AppUser : IdentityUser
    {
        public String FullName { get; set; }
    }
}
