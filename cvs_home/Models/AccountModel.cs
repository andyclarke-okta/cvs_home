using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace okta_aspnetcore_mvc_example.Models
{
 


    //public class GrantModel
    //{
    //    public Class1[] Property1 { get; set; }
    //}

    public class GrantModel
    {
        public string id { get; set; }
        public string status { get; set; }
        public DateTime created { get; set; }
        public Createdby createdBy { get; set; }
        public DateTime lastUpdated { get; set; }
        public string issuer { get; set; }
        public string clientId { get; set; }
        public string userId { get; set; }
        public string scopeId { get; set; }
        public string source { get; set; }
        public _Links _links { get; set; }
    }

    public class Createdby
    {
        public string id { get; set; }
        public string type { get; set; }
    }

    public class _Links
    {
        public App app { get; set; }
        public Authorizationserver authorizationServer { get; set; }
        public Scope scope { get; set; }
        public Self self { get; set; }
        public Client client { get; set; }
        public User user { get; set; }
    }

    public class App
    {
        public string href { get; set; }
        public string title { get; set; }
    }

    public class Authorizationserver
    {
        public string href { get; set; }
        public string title { get; set; }
    }

    public class Scope
    {
        public string href { get; set; }
        public string title { get; set; }
    }

    public class Self
    {
        public string href { get; set; }
        public Hints hints { get; set; }
    }

    public class Hints
    {
        public string[] allow { get; set; }
    }

    public class Client
    {
        public string href { get; set; }
        public string title { get; set; }
    }

    public class User
    {
        public string href { get; set; }
        public string title { get; set; }
    }


}
