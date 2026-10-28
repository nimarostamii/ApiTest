
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi.Models;
using TestApi.Authorization;

var builder = WebApplication.CreateBuilder(args);

// ======================================================
// Controllers
// ======================================================
builder.Services.AddControllers();

// ======================================================
// CORS - مناسب تست
// ======================================================
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy
            .AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader();
    });
});

// ======================================================
// Swagger
// ======================================================
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "TestApi",
        Version = "v1"
    });

    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter your JWT token"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// ======================================================
// OAuth configuration
// ======================================================
var oauthAuthority =
    builder.Configuration["OAuthServiceInfo:Authority"]
    ?? "https://localhost:7104";

var oauthBaseUrl =
    builder.Configuration["OAuthServiceInfo:BaseUrl"]
    ?? oauthAuthority;

// ======================================================
// Authentication - JWT
// ======================================================
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = oauthAuthority;
        options.RequireHttpsMetadata = false;

        // فقط برای محیط توسعه و گواهی Self-signed
        if (builder.Environment.IsDevelopment())
        {
            options.BackchannelHttpHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback =
                    HttpClientHandler
                        .DangerousAcceptAnyServerCertificateValidator
            };
        }

        options.TokenValidationParameters.ValidateAudience = false;
    });

// ======================================================
// Authorization policies
// ======================================================
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("WeatherForecastPermission", policy =>
    {
        policy.RequireAuthenticatedUser();

        policy.Requirements.Add(
            new PermissionRequirement("TestApi.WeatherForecast"));
    });

    options.AddPolicy("WeatherForecastGetPermissionTest2", policy =>
    {
        policy.RequireAuthenticatedUser();

        policy.Requirements.Add(
            new PermissionRequirement("TestApi.WeatherForecast.Get1"));
    });
});

// ======================================================
// HttpContext
// ======================================================
builder.Services.AddHttpContextAccessor();

// ======================================================
// OAuth Permission Validation HttpClient
// ======================================================
builder.Services
    .AddHttpClient("OAuthService", client =>
    {
        client.BaseAddress = new Uri(
            oauthBaseUrl.TrimEnd('/') + "/");

        client.Timeout = TimeSpan.FromSeconds(30);
    })
    .ConfigurePrimaryHttpMessageHandler(() =>
    {
        var handler = new HttpClientHandler();

        // فقط برای محیط توسعه و گواهی Self-signed
        if (builder.Environment.IsDevelopment())
        {
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler
                    .DangerousAcceptAnyServerCertificateValidator;
        }

        return handler;
    });

// ======================================================
// Authorization Handler
// ======================================================
builder.Services.AddSingleton<
    IAuthorizationHandler,
    PermissionAuthorizationHandler>();

// ======================================================
// Build
// ======================================================
var app = builder.Build();

// ======================================================
// Swagger
// ======================================================
app.UseSwagger();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint(
        "/swagger/v1/swagger.json",
        "TestApi v1");
});

// ======================================================
// Middleware
// ======================================================
app.UseRouting();

app.UseCors("AllowAll");

app.UseAuthentication();
app.UseAuthorization();

// ======================================================
// Controllers
// ======================================================
app.MapControllers();

// ======================================================
// Run
// ======================================================
app.Run();
