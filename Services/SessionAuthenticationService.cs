using Final8Net.Interfaces;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace Final8Net.Services
{
    public class SessionAuthenticationService : IAuthenticationServices
    {
        public bool IsAuthenticated(HttpContext httpContext)
        {
            // Check if the user is authenticated based on session
            return httpContext.Session.GetInt32("UserId") != null;
        }
    }
}
