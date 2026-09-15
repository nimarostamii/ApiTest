using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;

namespace TestApi.Authorization;

public sealed class PermissionAuthorizationHandler
    : AuthorizationHandler<PermissionRequirement>
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<PermissionAuthorizationHandler> _logger;

    public PermissionAuthorizationHandler(
        IHttpClientFactory httpClientFactory,
        IHttpContextAccessor httpContextAccessor,
        ILogger<PermissionAuthorizationHandler> logger)
    {
        _httpClientFactory = httpClientFactory;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionRequirement requirement)
    {
        var httpContext = _httpContextAccessor.HttpContext;

        _logger.LogInformation(
            "========== PermissionAuthorizationHandler START ==========");

        _logger.LogInformation(
            "Required Permission: {Permission}",
            requirement.PermissionName);

        if (httpContext == null)
        {
            _logger.LogWarning("HttpContext پیدا نشد.");
            return;
        }

        // =====================================================
        // Claims
        // =====================================================

        var clientId =
            context.User.FindFirst("client_id")?.Value;

        var userId =
            context.User.FindFirst("sub")?.Value
            ?? context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        _logger.LogInformation(
            "JWT Claims => ClientId: {ClientId}, UserId: {UserId}",
            clientId,
            userId);

        if (string.IsNullOrWhiteSpace(clientId))
        {
            _logger.LogWarning("client_id claim پیدا نشد.");
            return;
        }

        // =====================================================
        // Get Bearer Token
        // =====================================================

        var authorizationHeader =
            httpContext.Request.Headers.Authorization.FirstOrDefault();

        if (string.IsNullOrWhiteSpace(authorizationHeader))
        {
            _logger.LogWarning("Authorization Header وجود ندارد.");
            return;
        }

        if (!authorizationHeader.StartsWith(
                "Bearer ",
                StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "Authorization Header از نوع Bearer نیست.");
            return;
        }

        var accessToken =
            authorizationHeader["Bearer ".Length..].Trim();

        if (string.IsNullOrWhiteSpace(accessToken))
        {
            _logger.LogWarning("Access Token خالی است.");
            return;
        }

        // =====================================================
        // Build Validation Request
        // =====================================================

        var requestBody = new ValidateAccessRequest
        {
            ClientId = clientId,
            UserId = userId,
            PermissionName = requirement.PermissionName,
            IpAddress = httpContext.Connection.RemoteIpAddress?.ToString(),
            RequestTime = DateTime.UtcNow
        };

        // =====================================================
        // OAuthService
        // =====================================================

        var client =
            _httpClientFactory.CreateClient("OAuthService");

        using var request =
            new HttpRequestMessage(
                HttpMethod.Post,
                "/api/admin/AccessValidation/validate");

        request.Content =
            JsonContent.Create(requestBody);

        request.Headers.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                accessToken);

        try
        {
            _logger.LogInformation(
                "Calling OAuthService Permission Validation...");

            using var response =
                await client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    httpContext.RequestAborted);

            var responseContent =
                await response.Content.ReadAsStringAsync(
                    httpContext.RequestAborted);

            _logger.LogInformation(
                "OAuthService HTTP Response => StatusCode: {StatusCode}",
                (int)response.StatusCode);

            _logger.LogInformation(
                "OAuthService Response Body => {Body}",
                responseContent);

            // =================================================
            // HTTP Status
            // =================================================

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "OAuthService returned HTTP error. Status: {Status}",
                    (int)response.StatusCode);

                return;
            }

            if (string.IsNullOrWhiteSpace(responseContent))
            {
                _logger.LogError(
                    "OAuthService response body خالی است.");

                return;
            }

            // =================================================
            // Deserialize
            // =================================================

            ValidateAccessResult? result;

            try
            {
                result =
                    JsonSerializer.Deserialize<ValidateAccessResult>(
                        responseContent,
                        new JsonSerializerOptions
                        {
                            PropertyNameCaseInsensitive = true
                        });
            }
            catch (JsonException ex)
            {
                _logger.LogError(
                    ex,
                    "Deserialize پاسخ OAuthService شکست خورد.");

                return;
            }

            if (result == null)
            {
                _logger.LogError(
                    "OAuthService result == null");

                return;
            }

            // =================================================
            // Log Validation Result
            // =================================================

            _logger.LogInformation(
                "OAuth Result => IsSuccess: {IsSuccess}, Status: {Status}, Message: {Message}",
                result.IsSuccess,
                result.Status,
                result.Message);

            if (result.Data == null)
            {
                _logger.LogWarning(
                    "OAuth Result.Data == null");

                return;
            }

            _logger.LogInformation(
                "OAuth Data => HasAccess: {HasAccess}, PermissionsCount: {Count}",
                result.Data.HasAccess,
                result.Data.Permissions?.Count ?? 0);

            // =================================================
            // Find Permission
            // =================================================

            var permission =
                result.Data.Permissions?
                    .FirstOrDefault(x =>
                        string.Equals(
                            x.PermissionName,
                            requirement.PermissionName,
                            StringComparison.OrdinalIgnoreCase));

            if (permission == null)
            {
                _logger.LogWarning(
                    "Permission پیدا نشد. Required: {Permission}",
                    requirement.PermissionName);

                return;
            }

            _logger.LogInformation(
                "Permission Found => Name: {PermissionName}, IsGranted: {IsGranted}",
                permission.PermissionName,
                permission.IsGranted);

            // =================================================
            // Permission Granted?
            // =================================================

            if (!result.IsSuccess)
            {
                _logger.LogWarning(
                    "OAuthService IsSuccess=false");

                return;
            }

            if (!result.Data.HasAccess)
            {
                _logger.LogWarning(
                    "OAuthService HasAccess=false");

                return;
            }

            if (!permission.IsGranted)
            {
                _logger.LogWarning(
                    "Permission IsGranted=false");

                return;
            }

            // =================================================
            // Convert AccessList.Items -> AccessListValues
            // =================================================

            if (permission.DataAccessRules != null)
            {
                foreach (var rule in permission.DataAccessRules)
                {
                    if (rule.Conditions == null)
                        continue;

                    foreach (var condition in rule.Conditions)
                    {
                        if (condition.AccessList?.Items == null)
                            continue;

                        condition.AccessListValues =
                            condition.AccessList.Items
                                .Where(x =>
                                    !string.IsNullOrWhiteSpace(x.Value))
                                .Select(x => x.Value!)
                                .ToList();
                    }
                }
            }

            // =================================================
            // Data Access Rules
            // =================================================

            var rulesCount =
                permission.DataAccessRules?.Count ?? 0;

            _logger.LogInformation(
                "DataAccessRules Count: {Count}",
                rulesCount);

            if (permission.DataAccessRules != null)
            {
                foreach (var rule in permission.DataAccessRules)
                {
                    _logger.LogInformation(
                        "Rule => RuleId: {RuleId}, RuleName: {RuleName}, Priority: {Priority}, IsActive: {IsActive}, Conditions: {ConditionsCount}",
                        rule.RuleId,
                        rule.RuleName,
                        rule.Priority,
                        rule.IsActive,
                        rule.Conditions?.Count ?? 0);

                    if (rule.Conditions != null)
                    {
                        foreach (var condition in rule.Conditions)
                        {
                            _logger.LogInformation(
                                "Condition => ConditionId: {ConditionId}, Field: {FieldName}, Operator: {Operator}, DataType: {DataType}, FilterValue: {FilterValue}, AccessListId: {AccessListId}, AccessListValuesCount: {AccessListValuesCount}, Dynamic: {Dynamic}",
                                condition.ConditionId,
                                condition.FieldName,
                                condition.OperatorType,
                                condition.DataType,
                                condition.FilterValue,
                                condition.AccessListId,
                                condition.AccessListValues?.Count ?? 0,
                                condition.UseDynamicValue);
                        }
                    }
                }
            }

            // =================================================
            // FINAL SUCCESS
            // =================================================

            _logger.LogInformation(
                "##################################################");

            _logger.LogInformation(
                "PERMISSION AUTHORIZATION SUCCESS");

            _logger.LogInformation(
                "Permission: {Permission}",
                requirement.PermissionName);

            _logger.LogInformation(
                "ClientId: {ClientId}",
                clientId);

            _logger.LogInformation(
                "UserId: {UserId}",
                userId);

            _logger.LogInformation(
                "##################################################");

            httpContext.Items["PermissionAccess"] = permission;

            context.Succeed(requirement);
        }
        catch (OperationCanceledException)
            when (httpContext.RequestAborted.IsCancellationRequested)
        {
            _logger.LogWarning(
                "Permission validation request cancelled.");

            return;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(
                ex,
                "خطا در ارتباط با OAuthService.");

            return;
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "خطای غیرمنتظره در PermissionAuthorizationHandler.");

            return;
        }
    }

    // =========================================================
    // Request DTO
    // =========================================================

    public sealed class ValidateAccessRequest
    {
        public string ClientId { get; set; } = null!;

        public string? UserId { get; set; }

        public string PermissionName { get; set; } = null!;

        public string? IpAddress { get; set; }

        public DateTime? RequestTime { get; set; }
    }

    // =========================================================
    // Response DTO
    // =========================================================

    public sealed class ValidateAccessResult
    {
        public bool IsSuccess { get; set; }

        public string? Message { get; set; }

        public int? Status { get; set; }

        public ValidateAccessData? Data { get; set; }
    }

    public sealed class ValidateAccessData
    {
        public bool HasAccess { get; set; }

        public List<PermissionResult> Permissions { get; set; } = [];
    }

    public sealed class PermissionResult
    {
        public string? PermissionName { get; set; }

        public string? AccessObjectName { get; set; }

        public bool IsGranted { get; set; }

        public List<TimeRestrictionResult> TimeRestrictions { get; set; } = [];

        public List<DataAccessRuleResult> DataAccessRules { get; set; } = [];
    }

    public sealed class TimeRestrictionResult
    {
        public Guid Id { get; set; }

        public string? AllowedDaysOfWeek { get; set; }

        public string? AllowedTimeRanges { get; set; }

        public bool OnlyWorkingDays { get; set; }

        public bool OnlyHolidays { get; set; }

        public string? ExcludedDates { get; set; }

        public string? IncludedDates { get; set; }

        public bool IsActive { get; set; }

        public bool IsValidTime { get; set; }
    }

    public sealed class DataAccessRuleResult
    {
        public Guid Id { get; set; }

        public Guid RuleId { get; set; }

        public Guid SubjectAccessId { get; set; }

        public string? RuleName { get; set; }

        public int LogicalOperator { get; set; }

        public int Priority { get; set; }

        public bool IsActive { get; set; }

        public List<TimeRestrictionResult> TimeRestrictions { get; set; } = [];

        public List<DataFilterConditionResult> Conditions { get; set; } = [];
    }

    public sealed class DataFilterConditionResult
    {
        public Guid Id { get; set; }

        public Guid ConditionId { get; set; }

        public string? FieldName { get; set; }

        public int OperatorType { get; set; }

        public int DataType { get; set; }

        public string? FilterValue { get; set; }

        public Guid? AccessListId { get; set; }

        public AccessListResult? AccessList { get; set; }

        public bool IsActive { get; set; }

        public bool UseDynamicValue { get; set; }

        public string? DynamicValueSource { get; set; }

        public List<string> AccessListValues { get; set; } = [];
    }

    public sealed class AccessListResult
    {
        public Guid Id { get; set; }

        public Guid AccessListId { get; set; }

        public string Name { get; set; } = null!;

        public string? Code { get; set; }

        public string? Description { get; set; }

        public int ListType { get; set; }

        public int DataType { get; set; }

        public int? SubjectType { get; set; }

        public string? SubjectId { get; set; }

        public string? ExternalSourceConfig { get; set; }

        public int? RefreshIntervalMinutes { get; set; }

        public DateTime? LastSyncTime { get; set; }

        public int ItemCount { get; set; }

        public bool IsActive { get; set; }

        public List<AccessListItemResult> Items { get; set; } = [];
    }

    public sealed class AccessListItemResult
    {
        public Guid Id { get; set; }

        public Guid AccessListId { get; set; }

        public string Value { get; set; } = null!;

        public string? DisplayName { get; set; }

        public string? Metadata { get; set; }

        public bool IsAllowed { get; set; }

        public DateTime? ValidFrom { get; set; }

        public DateTime? ValidTo { get; set; }

        public bool IsActive { get; set; }
    }
}