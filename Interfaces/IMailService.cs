using extranlLoginAPI.Services;

namespace extranlLoginAPI.Interfaces
{
    public interface IMailService
    {
        void SendEmail(MailRequest mailRequest);
    }
}
