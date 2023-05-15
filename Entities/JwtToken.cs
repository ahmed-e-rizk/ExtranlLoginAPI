namespace extranlLoginAPI.Entities
{
    public class JwtToken
    {
        public string Token { get; set; }
        public DateTime ExpirationDate { get; set; }
    }
}
