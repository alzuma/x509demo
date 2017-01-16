using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using Common;

namespace Client
{
    public class Program
    {
        public static void Main(string[] args)
        {
            RunAsync().Wait();
        }

        static async Task RunAsync()
        {
            const string thumprint = "{your x.509 cert thumprint goes here}";

            //capture the current time
            var uxTime = DateTime.UtcNow.UnixTimeStampTime();

            //user name
            const string terminal = "t1";

            //sign
            var secure = new Secure();
            var key = HttpUtility.UrlEncode(secure.Sign($"{terminal}{uxTime}", thumprint));            


            var httpClient = new HttpClient();
            var uri = $"http://localhost:5000/api/values?key={key}&time={uxTime}&terminal={terminal}&thumprint={thumprint}";

            HttpResponseMessage response;
            try
            {
                response = await httpClient.GetAsync(uri);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                Console.ReadLine();
                return;
            }

            Console.WriteLine($"StatusCode: {response.StatusCode}");
            Console.ReadLine();
        }
    }
}
