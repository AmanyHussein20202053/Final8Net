namespace Final8Net.Interfaces
{
    public interface IEmailSign
    {
        Task SendEmailLoginlAsync(string email, string subject, string message, string verificationCode);
    }
}
