namespace TareaWebIdentity.Dto
{
    public class RegisterDto
    {
        public string Email { get; set; }
        public string FullName { get; set; }
        public string Password { get; set; }
        public string[] Roles { get; set; }
    }
}
