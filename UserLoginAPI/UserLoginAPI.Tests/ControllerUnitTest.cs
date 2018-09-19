using Microsoft.AspNetCore.Mvc;
using Moq;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UserLoginAPI.Controllers;
using UserLoginAPI.Models;
using UserLoginAPI.Services;
using Xunit;

namespace UserLoginAPI.Tests
{
    public class ControllerUnitTest
    {
        ControllerUnitTestHelper mockHelper = new ControllerUnitTestHelper();

        [Fact]
        public async void TestGetUserByID() 
        {
            Mock<IUsersControllerService> mockService = new Mock<IUsersControllerService>();
            mockService.Setup(service => service.GetUser(1)).Returns(mockHelper.GetTestResultData());
            UsersController controller = new UsersController(mockService.Object);

            var result = await controller.GetUser(1);
            OkObjectResult objectResult = result as OkObjectResult;
            User objectResultValue = objectResult.Value as User;

            Assert.Equal(200, objectResult.StatusCode);
        }

        [Fact]
        public async void TestGetUserByEmail()
        {
            Mock<IUsersControllerService> mockService = new Mock<IUsersControllerService>();
            mockService.Setup(service => service.GetUserByEmail("john.doe@test.com")).Returns(mockHelper.GetTestResultData());
            UsersController controller = new UsersController(mockService.Object);

            var result = await controller.GetUserByEmail("john.doe@test.com");
            OkObjectResult objectResult = result as OkObjectResult;
            User objectResultValue = objectResult.Value as User;

            Assert.Equal(200, objectResult.StatusCode);
        }

        [Fact]
        public async void TestPutUser()
        {
            User mockUser = await mockHelper.GetTestResultData();

            Mock<IUsersControllerService> mockService = new Mock<IUsersControllerService>();
            mockService.Setup(service => service.PutUser(mockUser)).Returns(mockHelper.GetTestResultData());
            UsersController controller = new UsersController(mockService.Object);

            var result = await controller.PutUser(1, mockUser);
            NoContentResult objectResult = result as NoContentResult;
            //User objectResultValue = objectResult.Value as User;

            Assert.Equal(204, objectResult.StatusCode);
        }

        [Fact]
        public async void TestPostUser()
        {
            User mockUser = await mockHelper.GetTestResultData();

            Mock<IUsersControllerService> mockService = new Mock<IUsersControllerService>();
            mockService.Setup(service => service.PostUser(mockUser)).Returns(mockHelper.GetTestResultData());
            UsersController controller = new UsersController(mockService.Object);

            var result = await controller.PostUser(mockUser);
            CreatedAtActionResult objectResult = result as CreatedAtActionResult;
            User objectResultValue = objectResult.Value as User;

            Assert.Equal(201, objectResult.StatusCode);
        }

        //[Fact]
        //public async void TestLogin()
        //{
        //    User mockUser = await mockHelper.GetTestResultData();
        //    Login mockLogin = await mockHelper.GetTestLoginData();

        //    Mock<IUsersControllerService> mockService = new Mock<IUsersControllerService>();
        //    mockService.Setup(service => service.Login(mockLogin.Email, mockLogin.Password)).Returns(mockHelper.GetTestLoginToken());
        //    UsersController controller = new UsersController(mockService.Object);

        //    var result = await controller.Login(mockLogin);
        //    OkObjectResult objectResult = result as OkObjectResult;
        //    User objectResultValue = objectResult.Value as User;

        //    Assert.Equal(200, objectResult.StatusCode);
        //}

        [Fact]
        public async void TestDeleteUser()
        {
            User mockUser = await mockHelper.GetTestResultData();

            Mock<IUsersControllerService> mockService = new Mock<IUsersControllerService>();
            mockService.Setup(service => service.DeleteUser(1)).Returns(mockHelper.GetTestResultData());
            UsersController controller = new UsersController(mockService.Object);

            var result = await controller.DeleteUser(1);
            OkObjectResult objectResult = result as OkObjectResult;
            User objectResultValue = objectResult.Value as User;

            Assert.Equal(200, objectResult.StatusCode);
        }

        //[Fact]
        //public void TestLogout()
        //{
        //    //User mockUser = await mockHelper.GetTestResultData();

        //    Mock<IUsersControllerService> mockService = new Mock<IUsersControllerService>();
        //    mockService.Setup(service => service.Lo(1)).Returns(mockHelper.GetTestResultData());
        //    UsersController controller = new UsersController(mockService.Object);

        //    var result = controller.Logout();
        //    OkObjectResult objectResult = result as OkObjectResult;
        //    User objectResultValue = objectResult.Value as User;

        //    Assert.Equal(200, objectResult.StatusCode);
        //}
    }
}
