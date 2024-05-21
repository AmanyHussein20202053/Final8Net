namespace Final8Net.Interfaces
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string email, string subject, string message, string verificationCode);
    }
}