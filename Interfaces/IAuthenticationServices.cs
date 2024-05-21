namespace Final8Net.Interfaces
{
    public interface IAuthenticationServices
    {
        bool IsAuthenticated(HttpContext httpContext);
    }
}
