using Consul;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UserLoginAPI.Models;

namespace UserLoginAPI.Services
{
    public class JwtTokenService : IJwtTokenService
    {
        Chilkat.Global glob = new Chilkat.Global();
        public string CreateToken(User user)
        {
            glob.UnlockBundle("Anything for 30-day trial");
            Chilkat.Rsa rsaKey = new Chilkat.Rsa();

            rsaKey.GenerateKey(1024);
            var rsaPrivKey = rsaKey.ExportPrivateKeyObj();

            var rsaPublicKey = rsaKey.ExportPublicKeyObj();
            var rsaPublicKeyAsString = rsaKey.ExportPublicKey();

            Chilkat.JsonObject jwtHeader = new Chilkat.JsonObject();
            jwtHeader.AppendString("alg", "RS256");
            jwtHeader.AppendString("typ", "JWT");

            Chilkat.JsonObject claims = new Chilkat.JsonObject();
            claims.AppendString("UserID", user.UserID.ToString());
            claims.AppendString("FirstName", user.FirstName);
            claims.AppendString("LastName", user.LastName);
            claims.AppendString("Email", user.Email);
            claims.AppendString("Contact", user.Contact.ToString());

            Chilkat.Jwt jwt = new Chilkat.Jwt();

            string token = jwt.CreateJwtPk(jwtHeader.Emit(), claims.Emit(), rsaPrivKey);
            using (var client = new ConsulClient())
            {
                client.Config.Address = new Uri("http://172.17.0.1:8500");
                var putPair = new KVPair("secretkey")
                {
                    Value = Encoding.UTF8.GetBytes(rsaPublicKeyAsString)
                };

                //var putAttempt = await client.KV.Put(putPair);

                //if (putAttempt.Response)
                //{
                //    var getPair = await client.KV.Get("secretkey");
                //    if (getPair.Response != null)
                //    {
                //        Console.WriteLine("Getting Back the Stored String");
                //        Console.WriteLine(Encoding.UTF8.GetString(getPair.Response.Value, 0, getPair.Response.Value.Length));
                //    }
                //}
            }
            return token;
        }
    }

    public interface IJwtTokenService
    {
        string CreateToken(User user);
    }
}
