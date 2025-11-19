using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace TrueLayer.ExampleWebhookServer;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddHttpClient("JwksClient", client =>
        {
            client.Timeout = System.TimeSpan.FromSeconds(30);
        });

        services.AddControllers();
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseRouting();
        app.UseEndpoints(endpoints => endpoints.MapControllers());
    }
}
