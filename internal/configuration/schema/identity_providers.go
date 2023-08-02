package schema

import (
	"crypto/rsa"
	"net/url"
	"time"
)

// IdentityProviders represents the Identity Providers configuration for Authelia.
type IdentityProviders struct {
	OIDC *IdentityProvidersOpenIDConnect `koanf:"oidc" json:"oidc"`
}

// IdentityProvidersOpenIDConnect represents the configuration for OpenID Connect 1.0.
type IdentityProvidersOpenIDConnect struct {
	HMACSecret        string `koanf:"hmac_secret" json:"hmac_secret" jsonschema:"title=HMAC Secret" jsonschema_description:"The HMAC Secret used to sign Access Tokens"`
	IssuerPrivateKeys []JWK  `koanf:"issuer_private_keys" json:"issuer_private_keys" jsonschema:"title=Issuer Private Keys" jsonschema_description:"The Private Keys used to sign ID Tokens"`

	IssuerCertificateChain X509CertificateChain `koanf:"issuer_certificate_chain" json:"issuer_certificate_chain" jsonschema:"title=Issuer Certificate Chain" jsonschema_description:"The Issuer Certificate Chain with an RSA Public Key used to sign ID Tokens"`
	IssuerPrivateKey       *rsa.PrivateKey      `koanf:"issuer_private_key" json:"issuer_private_key" jsonschema:"title=Issuer Private Key" jsonschema_description:"The Issuer Private Key with an RSA Private Key used to sign ID Tokens"`

	EnableClientDebugMessages bool `koanf:"enable_client_debug_messages" json:"enable_client_debug_messages" jsonschema:"default=false,title=Enable Client Debug Messages" jsonschema_description:"Enables additional debug messages for clients"`
	MinimumParameterEntropy   int  `koanf:"minimum_parameter_entropy" json:"minimum_parameter_entropy" jsonschema:"default=8,minimum=-1,title=Minimum Parameter Entropy" jsonschema_description:"The minimum entropy of the nonce parameter"`

	EnforcePKCE              string `koanf:"enforce_pkce" json:"enforce_pkce" jsonschema:"default=public_clients_only,enum=public_clients_only,enum=never,enum=always,title=Enforce PKCE" jsonschema_description:"Controls enforcement of the use of Proof Key for Code Exchange on all clients"`
	EnablePKCEPlainChallenge bool   `koanf:"enable_pkce_plain_challenge" json:"enable_pkce_plain_challenge" jsonschema:"default=false,title=Enable PKCE Plain Challenge" jsonschema_description:"Enables use of the discouraged plain Proof Key for Code Exchange challenges"`

	PAR  IdentityProvidersOpenIDConnectPAR  `koanf:"pushed_authorizations" json:"pushed_authorizations" jsonschema:"title=Pushed Authorizations" jsonschema_description:"Configuration options for Pushed Authorization Requests"`
	CORS IdentityProvidersOpenIDConnectCORS `koanf:"cors" json:"cors" jsonschema:"title=CORS" jsonschema_description:"Configuration options for Cross-Origin Request Sharing"`

	Clients []IdentityProvidersOpenIDConnectClient `koanf:"clients" json:"clients" jsonschema:"title=Clients" jsonschema_description:"OpenID Connect 1.0 clients registry"`

	AuthorizationPolicies map[string]OpenIDConnectPolicy          `koanf:"authorization_policies" json:"authorization_policies" jsonschema:"title=Authorization Policies" jsonschema_description:"Custom client authorization policies"`
	Lifespans             IdentityProvidersOpenIDConnectLifespans `koanf:"lifespans" json:"lifespans" jsonschema:"title=Lifespans" jsonschema_description:"Token lifespans configuration"`

	Discovery OpenIDConnectDiscovery `json:"-"` // MetaData value. Not configurable by users.
}

// OpenIDConnectPolicy configuration for OpenID Connect 1.0 authorization policies.
type OpenIDConnectPolicy struct {
	DefaultPolicy string `koanf:"default_policy" json:"default_policy" jsonschema:"enum=one_factor,enum=two_factor,enum=deny,title=Default Policy" jsonschema_description:"The default policy action for this policy"`

	Rules []OpenIDConnectPolicyRule `koanf:"rules" json:"rules" jsonschema:"title=Rules" jsonschema_description:"The list of rules for this policy"`
}

// OpenIDConnectPolicyRule configuration for OpenID Connect 1.0 authorization policies rules.
type OpenIDConnectPolicyRule struct {
	Policy   string                    `koanf:"policy" json:"policy" jsonschema:"enum=one_factor,enum=two_factor,enum=deny,title=Policy" jsonschema_description:"The policy to apply to this rule"`
	Subjects AccessControlRuleSubjects `koanf:"subject" json:"subject" jsonschema:"title=Subject" jsonschema_description:"Allows tuning the token lifespans for the authorize code grant"`
}

// OpenIDConnectDiscovery is information discovered during validation reused for the discovery handlers.
type OpenIDConnectDiscovery struct {
	AuthorizationPolicies       []string
	Lifespans                   []string
	DefaultKeyIDs               map[string]string
	DefaultKeyID                string
	ResponseObjectSigningKeyIDs []string
	ResponseObjectSigningAlgs   []string
	RequestObjectSigningAlgs    []string
}

type IdentityProvidersOpenIDConnectLifespans struct {
	IdentityProvidersOpenIDConnectLifespanToken `koanf:",squash"`
	Custom                                      map[string]IdentityProvidersOpenIDConnectLifespan `koanf:"custom" json:"custom" jsonschema:"title=Custom Lifespans" jsonschema_description:"Allows creating custom lifespans to be used by individual clients"`
}

// IdentityProvidersOpenIDConnectLifespan allows tuning the lifespans for OpenID Connect 1.0 issued tokens.
type IdentityProvidersOpenIDConnectLifespan struct {
	IdentityProvidersOpenIDConnectLifespanToken `koanf:",squash"`

	Grants IdentityProvidersOpenIDConnectLifespanGrants `koanf:"grants" json:"grants" jsonschema:"title=Grant Types" jsonschema_description:"Allows tuning the token lifespans for individual grant types"`
}

// IdentityProvidersOpenIDConnectLifespanGrants allows tuning the lifespans for each grant type.
type IdentityProvidersOpenIDConnectLifespanGrants struct {
	AuthorizeCode     IdentityProvidersOpenIDConnectLifespanToken `koanf:"authorize_code" json:"authorize_code" jsonschema:"title=Authorize Code Grant" jsonschema_description:"Allows tuning the token lifespans for the authorize code grant"`
	Implicit          IdentityProvidersOpenIDConnectLifespanToken `koanf:"implicit" json:"implicit" jsonschema:"title=Implicit Grant" jsonschema_description:"Allows tuning the token lifespans for the implicit flow and grant"`
	ClientCredentials IdentityProvidersOpenIDConnectLifespanToken `koanf:"client_credentials" json:"client_credentials" jsonschema:"title=Client Credentials Grant" jsonschema_description:"Allows tuning the token lifespans for the client credentials grant"`
	RefreshToken      IdentityProvidersOpenIDConnectLifespanToken `koanf:"refresh_token" json:"refresh_token" jsonschema:"title=Refresh Token Grant" jsonschema_description:"Allows tuning the token lifespans for the refresh token grant"`
	JWTBearer         IdentityProvidersOpenIDConnectLifespanToken `koanf:"jwt_bearer" json:"jwt_bearer" jsonschema:"title=JWT Bearer Grant" jsonschema_description:"Allows tuning the token lifespans for the JWT bearer grant"`
}

// IdentityProvidersOpenIDConnectLifespanToken allows tuning the lifespans for each token type.
type IdentityProvidersOpenIDConnectLifespanToken struct {
	AccessToken   time.Duration `koanf:"access_token" json:"access_token" jsonschema:"default=60 minutes,title=Access Token Lifespan" jsonschema_description:"The duration an Access Token is valid for"`
	AuthorizeCode time.Duration `koanf:"authorize_code" json:"authorize_code" jsonschema:"default=1 minute,title=Authorize Code Lifespan" jsonschema_description:"The duration an Authorization Code is valid for"`
	IDToken       time.Duration `koanf:"id_token" json:"id_token" jsonschema:"default=60 minutes,title=ID Token Lifespan" jsonschema_description:"The duration an ID Token is valid for"`
	RefreshToken  time.Duration `koanf:"refresh_token" json:"refresh_token" jsonschema:"default=90 minutes,title=Refresh Token Lifespan" jsonschema_description:"The duration a Refresh Token is valid for"`
}

// IdentityProvidersOpenIDConnectPAR represents an OpenID Connect 1.0 PAR config.
type IdentityProvidersOpenIDConnectPAR struct {
	Enforce         bool          `koanf:"enforce" json:"enforce" jsonschema:"default=false,title=Enforce" jsonschema_description:"Enforce the use of PAR for all requests on all clients"`
	ContextLifespan time.Duration `koanf:"context_lifespan" json:"context_lifespan" jsonschema:"default=5 minutes,title=Context Lifespan" jsonschema_description:"How long a PAR context is valid for"`
}

// IdentityProvidersOpenIDConnectCORS represents an OpenID Connect 1.0 CORS config.
type IdentityProvidersOpenIDConnectCORS struct {
	Endpoints      []string  `koanf:"endpoints" json:"endpoints" jsonschema:"uniqueItems,enum=authorization,enum=pushed-authorization-request,enum=token,enum=introspection,enum=revocation,enum=userinfo,title=Endpoints" jsonschema_description:"List of endpoints to enable CORS handling for"`
	AllowedOrigins []url.URL `koanf:"allowed_origins" json:"allowed_origins" jsonschema:"format=uri,title=Allowed Origins" jsonschema_description:"List of arbitrary allowed origins for CORS requests"`

	AllowedOriginsFromClientRedirectURIs bool `koanf:"allowed_origins_from_client_redirect_uris" json:"allowed_origins_from_client_redirect_uris" jsonschema:"default=false,title=Allowed Origins From Client Redirect URIs" jsonschema_description:"Automatically include the redirect URIs from the registered clients"`
}

// IdentityProvidersOpenIDConnectClient represents a configuration for an OpenID Connect 1.0 client.
type IdentityProvidersOpenIDConnectClient struct {
	ID               string          `koanf:"id" json:"id" jsonschema:"required,minLength=1,title=ID" jsonschema_description:"The Client ID"`
	Description      string          `koanf:"description" json:"description" jsonschema:"title=Description" jsonschema_description:"The Client Description for End-Users"`
	Secret           *PasswordDigest `koanf:"secret" json:"secret" jsonschema:"title=Secret" jsonschema_description:"The Client Secret for Client Authentication"`
	SectorIdentifier url.URL         `koanf:"sector_identifier" json:"sector_identifier" jsonschema:"title=Sector Identifier" jsonschema_description:"The Client Sector Identifier for Privacy Isolation"`
	Public           bool            `koanf:"public" json:"public" jsonschema:"default=false,title=Public" jsonschema_description:"Enables the Public Client Type"`

	RedirectURIs IdentityProvidersOpenIDConnectClientRedirectURIs `koanf:"redirect_uris" json:"redirect_uris" jsonschema:"required,title=Redirect URIs" jsonschema_description:"List of authorized redirect URIs"`

	Audience      []string `koanf:"audience" json:"audience" jsonschema:"uniqueItems,title=Audience" jsonschema_description:"List of authorized audiences"`
	Scopes        []string `koanf:"scopes" json:"scopes" jsonschema:"required,enum=openid,enum=offline_access,enum=groups,enum=email,enum=profile,uniqueItems,title=Scopes" jsonschema_description:"The Scopes this client is allowed request and be granted"`
	GrantTypes    []string `koanf:"grant_types" json:"grant_types" jsonschema:"enum=authorization_code,enum=implicit,enum=refresh_token,uniqueItems,title=Grant Types" jsonschema_description:"The Grant Types this client is allowed to use for the protected endpoints"`
	ResponseTypes []string `koanf:"response_types" json:"response_types" jsonschema:"enum=code,enum=id_token token,enum=id_token,enum=token,enum=code token,enum=code id_token,enum=code id_token token,uniqueItems,title=Response Types" jsonschema_description:"The Response Types the client is authorized to request"`
	ResponseModes []string `koanf:"response_modes" json:"response_modes" jsonschema:"enum=form_post,enum=query,enum=fragment,uniqueItems,title=Response Modes" jsonschema_description:"The Response Modes this client is authorized request"`

	AuthorizationPolicy string `koanf:"authorization_policy" json:"authorization_policy" jsonschema:"title=Authorization Policy" jsonschema_description:"The Authorization Policy to apply to this client"`
	Lifespan            string `koanf:"lifespan" json:"lifespan" jsonschema:"title=Lifespan Name" jsonschema_description:"The name of the custom lifespan to utilize for this client"`

	ConsentMode                  string         `koanf:"consent_mode" json:"consent_mode" jsonschema:"enum=auto,enum=explicit,enum=implicit,enum=pre-configured,title=Consent Mode" jsonschema_description:"The Consent Mode used for this client"`
	ConsentPreConfiguredDuration *time.Duration `koanf:"pre_configured_consent_duration" json:"pre_configured_consent_duration" jsonschema:"default=7 days,title=Pre-Configured Consent Duration" jsonschema_description:"The Pre-Configured Consent Duration when using Consent Mode pre-configured for this client"`

	EnforcePAR  bool `koanf:"enforce_par" json:"enforce_par" jsonschema:"default=false,title=Enforce PAR" jsonschema_description:"Enforces Pushed Authorization Requests for this client"`
	EnforcePKCE bool `koanf:"enforce_pkce" json:"enforce_pkce" jsonschema:"default=false,title=Enforce PKCE" jsonschema_description:"Enforces Proof Key for Code Exchange for this client"`

	PKCEChallengeMethod string `koanf:"pkce_challenge_method" json:"pkce_challenge_method" jsonschema:"enum=plain,enum=S256,title=PKCE Challenge Method" jsonschema_description:"The PKCE Challenge Method enforced on this client"`

	IDTokenSigningAlg           string `koanf:"id_token_signing_alg" json:"id_token_signing_alg" jsonschema:"eneum=none,enum=RS256,enum=RS384,enum=RS512,enum=ES256,enum=ES384,enum=ES512,enum=PS256,enum=PS384,enum=PS512,title=ID Token Signing Algorithm" jsonschema_description:"The algorithm (JWA) this client uses to sign ID Tokens"`
	IDTokenSigningKeyID         string `koanf:"id_token_signing_key_id" json:"id_token_signing_key_id" jsonschema:"title=ID Token Signing Key ID" jsonschema_description:"The Key ID this client uses to sign ID Tokens (overrides the 'id_token_signing_alg')"`
	UserinfoSigningAlg          string `koanf:"userinfo_signing_alg" json:"userinfo_signing_alg" jsonschema:"enum=none,enum=RS256,enum=RS384,enum=RS512,enum=ES256,enum=ES384,enum=ES512,enum=PS256,enum=PS384,enum=PS512,title=Userinfo Signing Algorithm" jsonschema_description:"The Userinfo Endpoint Signing Algorithm this client uses"`
	UserinfoSigningKeyID        string `koanf:"userinfo_signing_key_id" json:"userinfo_signing_key_id" jsonschema:"title=Userinfo Signing Key ID" jsonschema_description:"The Key ID this client uses to sign the userinfo responses (overrides the 'userinfo_token_signing_alg')"`
	RequestObjectSigningAlg     string `koanf:"request_object_signing_alg" json:"request_object_signing_alg" jsonschema:"enum=RS256,enum=RS384,enum=RS512,enum=ES256,enum=ES384,enum=ES512,enum=PS256,enum=PS384,enum=PS512,title=Request Object Signing Algorithm" jsonschema_description:"The Request Object Signing Algorithm the provider accepts for this client"`
	TokenEndpointAuthSigningAlg string `koanf:"token_endpoint_auth_signing_alg" json:"token_endpoint_auth_signing_alg" jsonschema:"enum=HS256,enum=HS384,enum=HS512,enum=RS256,enum=RS384,enum=RS512,enum=ES256,enum=ES384,enum=ES512,enum=PS256,enum=PS384,enum=PS512,title=Token Endpoint Auth Signing Algorithm" jsonschema_description:"The Token Endpoint Auth Signing Algorithm the provider accepts for this client"`

	TokenEndpointAuthMethod string `koanf:"token_endpoint_auth_method" json:"token_endpoint_auth_method" jsonschema:"enum=none,enum=client_secret_post,enum=client_secret_basic,enum=private_key_jwt,enum=client_secret_jwt,title=Token Endpoint Auth Method" jsonschema_description:"The Token Endpoint Auth Method enforced by the provider for this client"`

	PublicKeys IdentityProvidersOpenIDConnectClientPublicKeys `koanf:"public_keys" json:"public_keys,omitempty" jsonschema:"title=Public Keys" jsonschema_description:"Public Key options used to validate request objects and the 'private_key_jwt' client authentication method for this client"`

	Discovery OpenIDConnectDiscovery `json:"-"` // MetaData value. Not configurable by users.
}

// IdentityProvidersOpenIDConnectClientPublicKeys represents the Client Public Keys configuration for an OpenID Connect 1.0 client.
type IdentityProvidersOpenIDConnectClientPublicKeys struct {
	URI    *url.URL `koanf:"uri" json:"uri" jsonschema:"oneof_required=URI,title=URI" jsonschema_description:"URI of the JWKS endpoint which contains the Public Keys used to validate request objects and the 'private_key_jwt' client authentication method for this client"`
	Values []JWK    `koanf:"values" json:"values" jsonschema:"oneof_required=Values,title=Values" jsonschema_description:"List of arbitrary Public Keys used to validate request objects and the 'private_key_jwt' client authentication method for this client"`
}

// DefaultOpenIDConnectConfiguration contains defaults for OIDC.
var DefaultOpenIDConnectConfiguration = IdentityProvidersOpenIDConnect{
	Lifespans: IdentityProvidersOpenIDConnectLifespans{
		IdentityProvidersOpenIDConnectLifespanToken: IdentityProvidersOpenIDConnectLifespanToken{
			AccessToken:   time.Hour,
			AuthorizeCode: time.Minute,
			IDToken:       time.Hour,
			RefreshToken:  time.Minute * 90,
		},
	},
	EnforcePKCE: "public_clients_only",
}

var DefaultOpenIDConnectPolicyConfiguration = OpenIDConnectPolicy{
	DefaultPolicy: policyTwoFactor,
}

var defaultOIDCClientConsentPreConfiguredDuration = time.Hour * 24 * 7

// DefaultOpenIDConnectClientConfiguration contains defaults for OIDC Clients.
var DefaultOpenIDConnectClientConfiguration = IdentityProvidersOpenIDConnectClient{
	AuthorizationPolicy:          policyTwoFactor,
	Scopes:                       []string{"openid", "groups", "profile", "email"},
	ResponseTypes:                []string{"code"},
	ResponseModes:                []string{"form_post"},
	IDTokenSigningAlg:            "RS256",
	UserinfoSigningAlg:           "none",
	ConsentMode:                  "auto",
	ConsentPreConfiguredDuration: &defaultOIDCClientConsentPreConfiguredDuration,
}
