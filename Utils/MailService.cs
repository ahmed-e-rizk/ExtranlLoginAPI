using extranlLoginAPI.Interfaces;
using MimeKit;
using MailKit.Net.Smtp;
using extranlLoginAPI.Services;
namespace extranlLoginAPI.Services
{
    public class MailService : IMailService
    {
        public void SendEmail(MailRequest mailRequest)
        {
            var email = new MimeMessage
            {
                Sender = MailboxAddress.Parse("zeusfuks@gmail.com")
            };
            email.To.Add(MailboxAddress.Parse(mailRequest.ToEmail));
            email.Subject = mailRequest.Subject;
            var builder = new BodyBuilder
            {
                HtmlBody = mailRequest.Body
            };
            email.Body = builder.ToMessageBody();

            using var smtp = new SmtpClient();
            smtp.Connect("smtp.gmail.com", 465, true);
            smtp.Authenticate("zeusfuks@gmail.com", "yjrlubhbhqxnicgu");
            smtp.Send(email);
            smtp.Disconnect(true);
        }
    }
}
