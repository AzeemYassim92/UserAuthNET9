namespace UserAuth.Services
{

        public interface IEmailService
        {
            Task SendAsync(string toEmail, string subject, string body); 
        }

        public class EmailService: IEmailService
        {
            public Task SendAsync(string toEmail, string subject,string body)
            {
                Console.WriteLine($"[EMAIL] to: {toEmail}\nSubject {subject}\n{body}\n");
                return Task.CompletedTask; 
            }
        }
}
