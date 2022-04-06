using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using WebMvc.Extensions;
using WebMvc.Models;

namespace WebMvc.Services
{
    public interface IIdentityService
    {
        Task<AuthJwtResponse> Login(UserLogin userLogin);

        Task<AuthJwtResponse> Register(UserRegister userRegister);
    }

    public class IdentityService : Service, IIdentityService
    {
        private readonly HttpClient _httpClient;

        public IdentityService(HttpClient httpClient, IOptions<ApiServiceData> settings)
        {
            httpClient.BaseAddress = new Uri(settings.Value.IdentityUrl);
            _httpClient = httpClient;
        }

        public async Task<AuthJwtResponse> Login(UserLogin userLogin)
        {
            var content = GetContent(userLogin);

            var response = await _httpClient.PostAsync("/api/identity/signin", content);

            CheckResponseErrors(response);

            return await DeserializeResponse<AuthJwtResponse>(response);
        }

        public async Task<AuthJwtResponse> Register(UserRegister userRegister)
        {
            var content = GetContent(userRegister);

            var response = await _httpClient.PostAsync("/api/identity/new-account", content);

            CheckResponseErrors(response);

            return await DeserializeResponse<AuthJwtResponse>(response);
        }
    }
}