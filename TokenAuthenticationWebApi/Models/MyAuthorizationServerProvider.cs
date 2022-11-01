using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace TokenAuthenticationWebApi.Models
{
    public class MyAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {

            if (!context.TryGetBasicCredentials(out string clientID, out string clientSecret))
            {
                context.SetError("invalid_client", "Client credentials could not be retrieved through the Authorization header.");
                await Task.FromResult<object>(null);
            }

            ClientMaster client = (new ClientMasterRepository()).ValidateClient(clientID, clientSecret);
            if (client == null)
            {
                // Client could not be validated.
                context.SetError("invalid_client", "Client credentials are invalid.");
                await Task.FromResult<object>(null);
            }
            else
            {
                if (!client.Active)
                {
                    context.SetError("invalid_client", "Client is inactive.");
                    await Task.FromResult<object>(null);
                }
                // Client has been verified.
                context.OwinContext.Set<ClientMaster>("ta:client", client);
                context.OwinContext.Set<String>("ta:clientAllowedOrigin", client.AllowedOrigin);
                context.OwinContext.Set<String>("ta:clientRefreshTokenLifeTime", client.RefreshTokenLifeTime.ToString());
                context.Validated();
                await Task.FromResult<object>(null);
            }
        }
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            ClientMaster client = context.OwinContext.Get<ClientMaster>("ta:client");
            var allowedOrigin = context.OwinContext.Get<string>("ta:clientAllowedOrigin");

            if (allowedOrigin == null)
            {
                allowedOrigin = "*";
            }

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });

            UserMaster user = null;
            using (UserMasterRepository _repo = new UserMasterRepository())
            {
                user = _repo.ValidateUser(context.UserName, context.Password);
                if (user == null)
                {
                    context.SetError("invalid_grant", "Provided username and password is incorrect");
                    return;
                }
            }

            //client = context.OwinContext.Get<ClientMaster>("oauth:client");
            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            identity.AddClaim(new Claim(ClaimTypes.Role, user.UserRoles));
            identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
            identity.AddClaim(new Claim("Email", user.UserEmailID));
            /*                identity.AddClaim(new Claim("ClientID", client.ClientID));
                            identity.AddClaim(new Claim("ClientName", client.ClientName));
                            identity.AddClaim(new Claim("ClientSecret", client.ClientSecret));*/

            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    {
                        "client_id", (context.ClientId == null) ? string.Empty : context.ClientId
                    },
                    {
                        "userName", context.UserName
                    }
                });
            var ticket = new AuthenticationTicket(identity, props);
            context.Validated(ticket);
            await Task.Run(() => context.Validated(identity));

        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }
            return Task.FromResult<object>(null);
        }

        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary["client_id"];
            var currentClient = context.ClientId;
            if (originalClient != currentClient)
            {
                context.SetError("invalid_clientId", "Refresh token is issued to a different clientId.");
                return Task.FromResult<object>(null);
            }
            // Change auth ticket for refresh token requests
            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);
            newIdentity.AddClaim(new Claim("newClaim", "newValue"));
            var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);
            context.Validated(newTicket);
            return Task.FromResult<object>(null);
        }
    }
}