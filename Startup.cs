using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;

namespace SampleMvcApp
{




    public class AuthOptions
    {
        public const string ISSUER = "MyAuthServer"; // издатель токена
        public const string AUDIENCE = "MyAuthClient"; // потребитель токена
        const string KEY = "mysupersecret_secretkey!123";   // ключ для шифрации
        public const int LIFETIME = 1; // время жизни токена - 1 минута
        public static SymmetricSecurityKey GetSymmetricSecurityKey()
        {
            return new SymmetricSecurityKey(Encoding.ASCII.GetBytes(KEY));
        }
    }
    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment hostingEnvironment)
        {
            Configuration = configuration;
            HostingEnvironment = hostingEnvironment;
        }

        public IConfiguration Configuration { get; }
        public IWebHostEnvironment HostingEnvironment { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
            });

            ILogger logger = loggerFactory.CreateLogger<Startup>();
            logger.LogInformation("Example log message");

            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => HostingEnvironment.IsProduction();
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            //services.Configure<AuthorizationOptions>(options =>
            //{
            //    options.AddPolicy("ManageStore", policy => policy.RequireClaim("Action", "ManageStore"));
            //});



            // Add authentication services
            services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
                .AddCookie("Cookies")
                 .AddOpenIdConnect("oidc", options =>
                 {
                     options.Authority = $"https://{Configuration["Auth0:Domain"]}";
                     options.ClientId = Configuration["Auth0:ClientId"];
                     options.ClientSecret = Configuration["Auth0:ClientSecret"];

                     options.ResponseType = "code";
                     options.SaveTokens = true;
                     options.GetClaimsFromUserInfoEndpoint = false;

                     // Configure the scope
                     options.Scope.Clear();


                     options.Scope.Add("openid");
                     options.Scope.Add("profile");
                     options.Scope.Add("email");


                     options.ClaimActions.Clear();
                     //options.ClaimActions.MapJsonKey("resource_access", "resource_access");

                     options.CallbackPath = new PathString("/callback");

                     // Configure the Claims Issuer to be Auth0
                     options.ClaimsIssuer = "Auth0";
                     options.SaveTokens = true;
                     options.ClaimActions.MapCustomJson("resource_access_TEST", (o) =>
                     {
                         return "{\"oleg\": 1}";
                     });


                     // Set the correct name claim type
                     options.TokenValidationParameters = new TokenValidationParameters
                     {
                         NameClaimType = "name",
                         RoleClaimType = "https://schemas.quickstarts.com/roles",

                         //ValidateIssuer = false
                     };

                     options.Events = new OpenIdConnectEvents
                     {
                         OnAuthorizationCodeReceived = (context) =>
                         {
                             return Task.CompletedTask;
                         },
                         OnTokenValidated = (context) =>
                         {

                             var res = context.TokenEndpointResponse.AccessToken;

                             var claimsIdentity = (ClaimsIdentity)context.Principal.Identity;

                             var handler = new JwtSecurityTokenHandler();
                             var accessToken = handler.ReadJwtToken(res);


                             foreach (var claim in accessToken.Claims)
                             {
                                 if (!claimsIdentity.Claims.Contains(claim))
                                 {
                                     //                                     claimsIdentity.AddClaim(claim);
                                     logger.LogInformation($"Claim:{claim.Value}");
                                 }
                             }


                             return Task.CompletedTask;
                         },

                         OnAccessDenied = (context) =>
                         {
                             return Task.CompletedTask;

                         },
                         OnAuthenticationFailed = (context) =>
                         {
                             return Task.CompletedTask;
                         },
                         OnTokenResponseReceived = (context) =>
                         {
                             return Task.CompletedTask;
                         },
                         OnUserInformationReceived = context =>
                         {
                             return Task.CompletedTask;
                         },


                         // handle the logout redirection
                         OnRedirectToIdentityProviderForSignOut = (context) =>
                     {
                         //var logoutUri = $"https://{Configuration["Auth0:Domain"]}/v2/logout?client_id={Configuration["Auth0:ClientId"]}";
                         var logoutUri = $"https://atbauth.herokuapp.com/auth/realms/master/protocol/openid-connect/logout?client_id={Configuration["Auth0:ClientId"]}";

                         var postLogoutUri = context.Properties.RedirectUri;//"http://localhost:3000/";
                         if (!string.IsNullOrEmpty(postLogoutUri))
                         {
                             if (postLogoutUri.StartsWith("/"))
                             {
                                 // transform to absolute
                                 var request = context.Request;
                                 postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                             }
                             logoutUri += $"&returnTo={ Uri.EscapeDataString(postLogoutUri)}";
                         }

                         context.Response.Redirect(logoutUri);

                         //!!!!!!!!!!!!!!!!!!!!!!! remove coockies manually
                         context.Response.Cookies.Delete(".AspNetCore.Cookies");
                         context.HandleResponse();

                         return Task.CompletedTask;
                     }
                     };


                     //options.ClaimActions.Clear();
                     //options.ClaimActions.MapUniqueJsonKey(ClaimTypes.UserData, "resource_access");
                     //options.ClaimActions.MapJsonKey(ClaimTypes.Name, "resource_access");


                     //var jwtHandler = new JwtSecurityTokenHandler
                     //{
                     //    MapInboundClaims = false
                     //};

                     //options.SecurityTokenValidator = jwtHandler;

                     //options.SecurityTokenValidator = new JwtSecurityTokenHandler
                     //{
                     //    InboundClaimTypeMap = new Dictionary<string, string>()
                     //};
                     //options.TokenValidationParameters.NameClaimType = "resource_access";

                     //options.TokenValidationParameters = new TokenValidationParameters
                     //{
                     //    //NameClaimType = "resource_access",
                     //    NameClaimType = "resource_access"
                     //};
                 });


            //services.AddAuthorization(o =>
            //{

            //    o.a
            //});
            // Add framework services.
            services.AddControllersWithViews();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
