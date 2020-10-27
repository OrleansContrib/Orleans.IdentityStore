using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Orleans;
using Orleans.Configuration;
using Orleans.Hosting;
using Orleans.IdentityStore;
using System;
using System.Net;
using System.Threading.Tasks;

namespace ASPNetCoreHostedServices
{
    public static class Program
    {
        public static Task Main(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseOrleans(siloBuilder =>
                {
                    siloBuilder
                    .UseOrleanIdentityStore() // Add identity store
                    .UseLocalhostClustering()
                    .Configure<HostOptions>(options => options.ShutdownTimeout = TimeSpan.FromMinutes(1))
                    .Configure<ClusterOptions>(opts =>
                    {
                        opts.ClusterId = "dev";
                        opts.ServiceId = "HellowWorldService";
                    })
                    .Configure<EndpointOptions>(opts =>
                    {
                        opts.AdvertisedIPAddress = IPAddress.Loopback;
                    });
                })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.Configure((ctx, app) =>
                    {
                        if (ctx.HostingEnvironment.IsDevelopment())
                        {
                            app.UseDeveloperExceptionPage();
                        }

                        app.UseHttpsRedirection();
                        app.UseRouting();
                        app.UseAuthentication();
                        app.UseAuthorization();
                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapControllers();
                            endpoints.MapRazorPages();
                        });
                    });
                })
                .ConfigureServices(services =>
                {
                    services.AddControllers();
                    // Add identity
                    services.AddDefaultIdentity<IdentityUser<Guid>>()
                    // User orleans as the store
                    .AddOrleansStores();
                    services.AddRazorPages();
                })
            .RunConsoleAsync();
    }
}