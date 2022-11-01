using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using Newtonsoft.Json;

namespace RefreshTokenClient1
{
    class Program
    {
        // When your application is registered you will get 
        // the client id and secret from the API
        private static string _clientId = "DOTNET";
        private static string _clientSecret = "04301C50-1BC0-4A6F-9190-B4206BC027CB";
        private static string Username = "";
        private static string Password = "";
        //Store the base address of the web api
        //You need to change the PORT number where your WEB API service is running
        private static string baseAddress = "https://localhost:44331/";
        static void Main(string[] args)
        {
            Token token = null;
            Username = "Anurag";
            Password = "123456";
            // First get the token from the persistent storage based
            // on the username and password
            token = (new UserTokenRepository()).GetTokenFromDB(Username, Password);
            //Then check the existing token and its expiration datetime
            if (token != null && DateTime.Now < token.ExpiredDateTime)
            {
                //use the existing token
            }
            else if (token != null && !string.IsNullOrEmpty(token.RefreshToken))
            {
                //Get a new access token based on the Refresh Token
                token = GetTokens(_clientId, _clientSecret, token.RefreshToken);
            }
            else
            {
                //Get a brand new access token
                token = GetTokens(_clientId, _clientSecret, null);
            }
            //If you get the access token, then call the authorized resource 
            if (!string.IsNullOrEmpty(token.AccessToken))
            {
                CallAPIResource1(token.AccessToken);
            }
            else
            {
                Console.WriteLine(token.Error);
            }
            Console.ReadLine();
        }
        //Here we implment the logic to call the authorized resource
        private static void CallAPIResource1(string AccessToken)
        {
            HttpClientHandler handler = new HttpClientHandler();
            HttpClient client = new HttpClient(handler);
            // Need to set the Access Token in the Authorization Header as shown below
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", AccessToken);
            // Make a Get request for the authorized resource by invoking 
            // the PostAsync method on the client object as shown below
            var APIResponse = client.GetAsync(baseAddress + "api/test/resource1").Result;
            if (APIResponse.IsSuccessStatusCode)
            {
                var JsonContent = APIResponse.Content.ReadAsStringAsync().Result;
                string Message = JsonConvert.DeserializeObject<string>(JsonContent);
                Console.WriteLine("APIResponse : " + Message);
            }
            else
            {
                Console.WriteLine("APIResponse, Error : " + APIResponse.StatusCode);
            }
        }
        //In this method we need to implement the logic whether we need get a brand new access token
        // or we need the access token based on the Refresh Token
        private static Token GetTokens(string clientId, string clientSecret, string RefreshToken)
        {
            Token token = null;
            if (string.IsNullOrEmpty(RefreshToken))
            {
                token = GetAccessToken(clientId, clientSecret, Username, Password);
            }
            else
            {
                token = GetAccessTokenByRefreshToken(clientId, clientSecret, RefreshToken);
                // The Refresh token can become invalid for several reasons
                // such as invalid cliendid and secret or the user's password has changed.
                // In Such cases issue a brand new access token
                if (!string.IsNullOrEmpty(token.Error))
                {
                    token = GetAccessToken(clientId, clientSecret, Username, Password);
                }
            }
            if (!string.IsNullOrEmpty(token.Error))
            {
                throw new Exception(token.Error);
            }
            else
            {
                //Need to store the token in any presistent storage
                token.ExpiredDateTime = DateTime.Now.AddSeconds(token.ExpiresIn);
                //Create an object of type UserTokenMaster
                UserTokenMaster userTokenMaster = new UserTokenMaster()
                {
                    UserName = Username,
                    UserPassword = Password,
                    AccessToken = token.AccessToken,
                    RefreshToken = token.RefreshToken,
                    TokenExpiredTime = token.ExpiredDateTime
                };
                bool IsAddeded = (new UserTokenRepository()).AddUserTokenIntoDB(userTokenMaster);
                if (IsAddeded)
                {
                    token.Error = "Error Occurred while saving the Token into the DB";
                }
            }
            return token;
        }
        //This method is used to get a new access token
        public static Token GetAccessToken(string clientId, string clientSecret, string username, string password)
        {
            Token token = new Token();
            HttpClientHandler handler = new HttpClientHandler();
            HttpClient client = new HttpClient(handler);
            // Need to set the Client ID and Client Secret in the Authorization Header
            // in Base64 Encoded Format using the Basic Authentication as shown below
            string ClientIDandSecret = clientId + ":" + clientSecret;
            var authorizationHeader = Convert.ToBase64String(Encoding.UTF8.GetBytes(ClientIDandSecret));
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", authorizationHeader);
            // Create a dictionary which contains the request form data, here we need to set
            // the username, password and grant_type as shown below
            var RequestBody = new Dictionary<string, string>
            {
            {"grant_type", "password"},
            {"username", username},
            {"password", password},
            };
            //Make a Post request by invoking the PostAsync method on the client object as shown below
            var tokenResponse = client.PostAsync(baseAddress + "token", new FormUrlEncodedContent(RequestBody)).Result;
            if (tokenResponse.IsSuccessStatusCode)
            {
                var JsonContent = tokenResponse.Content.ReadAsStringAsync().Result;
                token = JsonConvert.DeserializeObject<Token>(JsonContent);
                token.Error = null;
            }
            else
            {
                token.Error = "GetAccessToken failed likely due to an invalid client ID, client secret, or invalid usrename and password";
            }
            return token;
        }
        //This method is used to get a new access token based on the Refresh Token
        public static Token GetAccessTokenByRefreshToken(string clientId, string clientSecret, string refreshToken)
        {
            Token token = new Token();
            HttpClientHandler handler = new HttpClientHandler();
            HttpClient client = new HttpClient(handler);
            // Need to set the Client ID and Client Secret in the Authorization Header
            // in Base64 Encoded Format using Basic Authentication as shown below
            string ClientIDandSecret = clientId + ":" + clientSecret;
            var authorizationHeader = Convert.ToBase64String(Encoding.UTF8.GetBytes(ClientIDandSecret));
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", authorizationHeader);
            // Create a dictionary which contains the refresh token, here we need to set
            // the grant_type as refresh_token as shown below
            var RequestBody = new Dictionary<string, string>
            {
            {"grant_type", "refresh_token"},
            {"refresh_token", refreshToken}
            };
            //Make a Post request by invoking the PostAsync method on the client object as shown below
            var tokenResponse = client.PostAsync(baseAddress + "token", new FormUrlEncodedContent(RequestBody)).Result;
            if (tokenResponse.IsSuccessStatusCode)
            {
                var JsonContent = tokenResponse.Content.ReadAsStringAsync().Result;
                token = JsonConvert.DeserializeObject<Token>(JsonContent);
                token.Error = null;
            }
            else
            {
                token.Error = "GetAccessToken by Refresh Token failed likely due to an invalid client ID, client secret, or it has been revoked by the system admin";
            }
            return token;
        }
    }
}