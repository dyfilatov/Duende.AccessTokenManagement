namespace Duende.AccessTokenManagement;

/// <summary>
/// Default values used by the token exchange token management components
/// </summary>
public static class TokenExchangeTokenManagementDefaults
{
    /// <summary>
    /// The name of the back-channel HTTP client used for token exchange requests.
    /// </summary>
    public const string BackChannelHttpClientName = "Duende.AccessTokenManagement.BackChannel";

    /// <summary>
    /// The name of the options key used to store the TokenRequestParameters in the TokenExchangeTokenRequest.Options dictionary.
    /// </summary>
    public const string TokenRequestParametersOptionsName = "TokenRequestParameters";
}