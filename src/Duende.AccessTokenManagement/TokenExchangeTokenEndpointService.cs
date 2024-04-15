using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Duende.AccessTokenManagement;

public class TokenExchangeTokenEndpointService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptionsMonitor<TokenExchangeClient> _options;
    private readonly IClientAssertionService _clientAssertionService;
    private readonly IDPoPKeyStore _dPoPKeyMaterialService;
    private readonly IDPoPProofService _dPoPProofService;
    private readonly ILogger<TokenExchangeTokenEndpointService> _logger;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="httpClientFactory"></param>
    /// <param name="clientAssertionService"></param>
    /// <param name="dPoPKeyMaterialService"></param>
    /// <param name="dPoPProofService"></param>
    /// <param name="logger"></param>
    /// <param name="options"></param>
    public TokenExchangeTokenEndpointService(
        IHttpClientFactory httpClientFactory,
        IOptionsMonitor<TokenExchangeClient> options,
        IClientAssertionService clientAssertionService,
        IDPoPKeyStore dPoPKeyMaterialService,
        IDPoPProofService dPoPProofService,
        ILogger<TokenExchangeTokenEndpointService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options;
        _clientAssertionService = clientAssertionService;
        _dPoPKeyMaterialService = dPoPKeyMaterialService;
        _dPoPProofService = dPoPProofService;
        _logger = logger;
    }

    /// <inheritdoc/>
    public virtual async Task<ClientCredentialsToken> RequestToken(
        string clientName,
        TokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        var client = _options.Get(clientName);

        if (string.IsNullOrWhiteSpace(client.TokenEndpoint) || string.IsNullOrEmpty(client.ClientId))
        {
            throw new InvalidOperationException("unknown client");
        }

        var request = new TokenExchangeTokenRequest
        {
            Address = client.TokenEndpoint,
            Scope = client.Scope,
            ClientId = client.ClientId,
            ClientSecret = client.ClientSecret,
            ClientCredentialStyle = client.ClientCredentialStyle,
            SubjectToken = parameters?.SubjectToken
        };

        request.Parameters.AddRange(client.Parameters);

        parameters ??= new TokenRequestParameters();

        if (!string.IsNullOrWhiteSpace(parameters.Scope))
        {
            request.Scope = parameters.Scope;
        }

        if (!string.IsNullOrWhiteSpace(parameters.Resource))
        {
            request.Resource.Clear();
            request.Resource.Add(parameters.Resource);
        }
        else if (!string.IsNullOrWhiteSpace(client.Resource))
        {
            request.Resource.Clear();
            request.Resource.Add(client.Resource);
        }

        request.Parameters.AddRange(parameters.Parameters);

        // if assertion gets passed in explicitly, use it.
        // otherwise call assertion service
        if (parameters.Assertion != null)
        {
            request.ClientAssertion = parameters.Assertion;
            request.ClientCredentialStyle = ClientCredentialStyle.PostBody;
        }
        else
        {
            var assertion = await _clientAssertionService.GetClientAssertionAsync(clientName).ConfigureAwait(false);
                
            if (assertion != null)
            {
                request.ClientAssertion = assertion;
                request.ClientCredentialStyle = ClientCredentialStyle.PostBody;
            }
        }
        
        request.Options.TryAdd(TokenExchangeTokenManagementDefaults.TokenRequestParametersOptionsName, parameters);

        var key = await _dPoPKeyMaterialService.GetKeyAsync(clientName);
        if (key != null)
        {
            _logger.LogDebug("Creating DPoP proof token for token request.");

            var proof = await _dPoPProofService.CreateProofTokenAsync(new DPoPProofRequest
            {
                Url = request.Address!,
                Method = "POST",
                DPoPJsonWebKey = key.JsonWebKey,
            });
            request.DPoPProofToken = proof?.ProofToken;
        }

        HttpClient httpClient;
        if (client.HttpClient != null)
        {
            httpClient = client.HttpClient;
        }
        else if (!string.IsNullOrWhiteSpace(client.HttpClientName))
        {
            httpClient = _httpClientFactory.CreateClient(client.HttpClientName);    
        }
        else
        {
            httpClient = _httpClientFactory.CreateClient(TokenExchangeTokenManagementDefaults.BackChannelHttpClientName);    
        }
        
        _logger.LogDebug("Requesting token exchange access token at endpoint: {endpoint}", request.Address);
        var response = await httpClient.RequestTokenExchangeTokenAsync(request, cancellationToken).ConfigureAwait(false);

        if (response.IsError && 
            (response.Error == OidcConstants.TokenErrors.UseDPoPNonce || response.Error == OidcConstants.TokenErrors.InvalidDPoPProof) && 
            key != null && 
            response.DPoPNonce != null)
        {
            _logger.LogDebug("Token request failed with DPoP nonce error. Retrying with new nonce.");

            var proof = await _dPoPProofService.CreateProofTokenAsync(new DPoPProofRequest
            {
                Url = request.Address!,
                Method = "POST",
                DPoPJsonWebKey = key.JsonWebKey,
                DPoPNonce = response.DPoPNonce
            });
            request.DPoPProofToken = proof?.ProofToken;

            if (request.DPoPProofToken != null)
            {
                response = await httpClient.RequestTokenExchangeTokenAsync(request, cancellationToken).ConfigureAwait(false);
            }
        }

        if (response.IsError)
        {
            return new ClientCredentialsToken
            {
                Error = response.Error
            };
        }
        
        return new ClientCredentialsToken
        {
            AccessToken = response.AccessToken,
            AccessTokenType = response.TokenType,
            DPoPJsonWebKey = key?.JsonWebKey,
            Expiration = response.ExpiresIn == 0
                ? DateTimeOffset.MaxValue
                : DateTimeOffset.UtcNow.AddSeconds(response.ExpiresIn),
            Scope = response.Scope
        };
    }
}
