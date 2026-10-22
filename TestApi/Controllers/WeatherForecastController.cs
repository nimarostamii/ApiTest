using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TestApi.Authorization;

namespace TestApi.Controllers;

[ApiController]
[Route("[controller]/[action]")]

[Authorize]
public class WeatherForecastController : ControllerBase
{
    private readonly ILogger<WeatherForecastController> _logger;

    public WeatherForecastController(
        ILogger<WeatherForecastController> logger)
    {
        _logger = logger;
    }

    [HttpGet]
    [Authorize(Policy = "WeatherForecastPermission")]
    public IEnumerable<WeatherForecast> Get()
    {
        var data = new[]
        {
            new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(1)),
                TemperatureC = 20,
                Summary = "Cool",
                DepartmentId = 10
            },
            new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(2)),
                TemperatureC = 25,
                Summary = "Mild",
                DepartmentId = 20
            },
            new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(3)),
                TemperatureC = 30,
                Summary = "Warm",
                DepartmentId = 30
            },
            new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(4)),
                TemperatureC = 35,
                Summary = "Hot",
                DepartmentId = 40
            }
        };

        // ????? Permission ?? AuthorizationHandler
        var permission =
            HttpContext.Items["PermissionAccess"]
                as PermissionAuthorizationHandler.PermissionResult;

        // ??? PermissionAccess ???? ?????? ????
        if (permission == null)
        {
            _logger.LogWarning(
                "PermissionAccess ?? HttpContext.Items ???? ???.");

            return [];
        }

        // ??? Permission ???? ?????
        if (!permission.IsGranted)
        {
            _logger.LogWarning(
                "Permission ???? ????. Permission: {Permission}",
                permission.PermissionName);

            return [];
        }

        var rules = permission.DataAccessRules;

        // ??? Rule ??????? ????? ??? ??????? ???? ?????
        if (rules == null || rules.Count == 0)
        {
            return data;
        }

        var result = data.AsEnumerable();

        foreach (var rule in rules)
        {
            if (!rule.IsActive)
                continue;

            if (rule.Conditions == null ||
                rule.Conditions.Count == 0)
                continue;

            foreach (var condition in rule.Conditions)
            {
                if (!condition.IsActive)
                    continue;

                // ????? ??? DepartmentId
                if (!string.Equals(
                        condition.FieldName,
                        "DepartmentId",
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // ????? AccessListValues ?? ????? ???????
                if (condition.AccessListValues == null ||
                    condition.AccessListValues.Count == 0)
                {
                    continue;
                }

                var allowedDepartmentIds =
                    condition.AccessListValues
                        .Select(x =>
                        {
                            return int.TryParse(x, out var value)
                                ? (int?)value
                                : null;
                        })
                        .Where(x => x.HasValue)
                        .Select(x => x!.Value)
                        .ToHashSet();

                result = result.Where(x =>
                    allowedDepartmentIds.Contains(
                        x.DepartmentId));
            }
        }

        return result;
    }


    [HttpGet]
    [Authorize(Policy = "WeatherForecastGetPermissionTest2")]
    public IEnumerable<WeatherForecast> Get1()
    {
        var data = new[]
        {
            new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(1)),
                TemperatureC = 55555,
                Summary = "Coollllllll",
                DepartmentId = 111111111
            }
        };

        
        return data;
    }
}