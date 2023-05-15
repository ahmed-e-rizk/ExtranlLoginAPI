namespace extranlLoginAPI.Entities
{
    public class ApiResponseWithToken
    {
        public bool Status { get; set; }
        public string Message { get; set; }
        public string Token { get; set; }
        public DateTime Expiration { get; set; }
    }
}
