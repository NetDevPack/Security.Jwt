using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Identity.Models
{

    public class UserLoginResponse
    {
        public UserLoginResponse(string at, string rf)
        {
            AccessToken = at;
            RefreshToken = rf;
            ExpiresIn = 3600;
        }

        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public int ExpiresIn { get; set; }
    }

    public class Token
    {
        [Required]
        [JsonPropertyName("refresh-token")]
        public string RefreshToken { get; set; }
    }

    public class UserRegister
    {
        [Required(ErrorMessage = "The {0} is required")]
        [EmailAddress(ErrorMessage = "The {0} is in a incorrect format")]
        public string Email { get; set; }

        [Required(ErrorMessage = "The {0} is required")]
        [StringLength(100, ErrorMessage = "The {0} must have between {2} and {1} characters", MinimumLength = 6)]
        public string Password { get; set; }

        [DisplayName("Confirm Password")]
        [Compare("Password", ErrorMessage = "The passwords doesn't match.")]
        public string ConfirmPassword { get; set; }
    }

    public class UserLogin
    {
        [Required(ErrorMessage = "The {0} is required")]
        [EmailAddress(ErrorMessage = "The {0} is in a incorrect format")]
        public string Email { get; set; }

        [Required(ErrorMessage = "The {0} is required")]
        [StringLength(100, ErrorMessage = "The {0} must have between {2} and {1} characters", MinimumLength = 6)]
        public string Password { get; set; }
    }
}