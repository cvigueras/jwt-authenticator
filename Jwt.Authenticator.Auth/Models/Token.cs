﻿namespace Jwt.Authenticator.Auth.Models
{
    public class Token
    {
        public string refresh_token { get; set; }
        public string access_token { get; set; }
        public int expires_in { get; set; }
    }
}