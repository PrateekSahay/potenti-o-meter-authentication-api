using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using UserLoginAPI.Models;

namespace UserLoginAPI.Tests
{
    class ControllerUnitTestHelper
    {
        public async Task<User> GetTestResultData()
        {
            var mockUser = new User()
            {
                UserID = 1,
                FirstName = "John",
                LastName = "Doe",
                Email = "john.doe@test.com",
                Contact = 987243,
                Password = "john@123"
            };

            return await Task.FromResult(mockUser);
        }

        public IEnumerable<User> GetTestResultDataArray()
        {
            var mockUser1 = new User()
            {
                UserID = 1,
                FirstName = "John",
                LastName = "Doe",
                Email = "john.doe@test.com",
                Contact = 987243,
                Password = "john@123"
            };

            var mockUser2 = new User()
            {
                UserID = 2,
                FirstName = "Jane",
                LastName = "Doe",
                Email = "jane.doe@test.com",
                Contact = 987233,
                Password = "jane@123"
            };

            List<User> mockUsers = new List<User>() { mockUser1, mockUser2 };

            return mockUsers;
        }

        public async Task<Login> GetTestLoginData()
        {
            var mockUser = new Login()
            {
                Email = "john.doe@example.com",
                Password = "john@123"
            };

            return await Task.FromResult(mockUser);
        }

        public async Task<String> GetTestLoginToken()
        {
            string token = "abcdeqwe";

            return await Task.FromResult(token);  
        }
    }
}
