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
// CORS - اجازه به همه (برای تست)
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
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "TestApi",
        Version = "v1"
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter JWT Bearer token"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Id = "Bearer",
                    Type = ReferenceType.SecurityScheme
                }
            },
            Array.Empty<string>()
        }
    });
});

// ======================================================
// Authentication - JWT
// ======================================================
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "https://localhost:7104";//"https://172.32.16.17";
        options.RequireHttpsMetadata = false;

        options.BackchannelHttpHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };

        options.TokenValidationParameters.ValidateAudience = false;
    });

// ======================================================
// Authorization
// ======================================================
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("WeatherForecastPermission", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.Requirements.Add(
            new PermissionRequirement("TestApi.WeatherForecast"));
    });
});

// ======================================================
// HttpContext
// ======================================================
builder.Services.AddHttpContextAccessor();

// ======================================================
// OAuth Permission Validation HttpClient
// ======================================================
builder.Services.AddHttpClient("OAuthService", client =>
{
    client.BaseAddress = new Uri("https://localhost:7104"); //https://172.32.16.17
    client.Timeout = TimeSpan.FromSeconds(30);
})
.ConfigurePrimaryHttpMessageHandler(() =>
{
    return new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback =
            HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
    };
});

// ======================================================
// Authorization Handler
// ======================================================
builder.Services.AddSingleton<IAuthorizationHandler, PermissionAuthorizationHandler>();

// ======================================================
// Build
// ======================================================
var app = builder.Build();

// ======================================================
// Swagger
// ======================================================
app.UseSwagger();
app.UseSwaggerUI();

// ======================================================
// CORS (باید قبل از Authentication باشد)
// ======================================================
app.UseCors("AllowAll");

// ======================================================
// HTTPS
// ======================================================
app.UseHttpsRedirection();

// ======================================================
// Authentication
// ======================================================
app.UseAuthentication();

// ======================================================
// Authorization
// ======================================================
app.UseAuthorization();

// ======================================================
// Controllers
// ======================================================
app.MapControllers();

// ======================================================
// Run
// ======================================================
app.Run();