using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Common;

namespace Server
{
    public class X509CheckMiddleware
    {
        private readonly RequestDelegate _next;

        public X509CheckMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext ctx)
        {
            try
            {
                //capture the current time
                var timeNow = DateTime.UtcNow.UnixTimeStampTime();

                //read data from url
                var terminal = ctx.Request.Query["terminal"];
                var time = ctx.Request.Query["time"];
                var key = ctx.Request.Query["key"];
                var thumprint = ctx.Request.Query["thumprint"];

                //verify key
                var secure = new Secure();
                var validKey = secure.Verify($"{terminal}{time}", key, thumprint);

                //calculate seconds between now and client sent in time
                var secondsBetweenCalls = timeNow - int.Parse(time);

                //if the key is valid and key isn't older than 5 seconds, let it pass
                if (validKey && secondsBetweenCalls <= 5)
                {
                    await _next(ctx);
                }
                else
                {
                    ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await ctx.Response.WriteAsync("");
                }
            }
            catch (Exception)
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await ctx.Response.WriteAsync("");
            }
        }
    }
}