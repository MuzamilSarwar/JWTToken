﻿namespace WebApplication1.Models
{
    public class UserDto
    {
        public string Name { get; set; } = string.Empty;
        public string Password {  get; set; }= string.Empty;
        public string Role {  get; set; } = string.Empty;
    }

    public class LoginDto
    {
        public string Name { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}
