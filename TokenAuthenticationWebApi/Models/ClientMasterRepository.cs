using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace TokenAuthenticationWebApi.Models
{
    public class ClientMasterRepository : IDisposable
    {
        // SECURITY_DBEntities it is your context class
        SECURITY_DBEntities1 context = new SECURITY_DBEntities1();

        //This method is used to check and validate the Client credentials
        public ClientMaster ValidateClient(string ClientID, string ClientSecret)
        {
            return context.ClientMasters.FirstOrDefault(user =>
             user.ClientId == ClientID
            && user.ClientSecret == ClientSecret);
        }
        public void Dispose()
        {
            context.Dispose();
        }
    }
}