namespace extranlLoginAPI.Services
{
    public class GeneratePasswordResetToken
    {
        public static string GenerateRandomNo()
        {
            int _min = 1000;
            int _max = 9999;
            Random _rdm = new();
            return (_rdm.Next(_min, _max)).ToString();
        }
    }
}
