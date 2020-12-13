using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Okta.AspNetCore;
using Okta.Sdk;
using Okta.Sdk.Configuration;
using okta_aspnetcore_mvc_example.Models;
using FluentEmail.Core;
using FluentEmail.Mailgun;
using okta_aspnetcore_mvc_example.Services;
using System.Security.Claims;
using RestSharp;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Http;

namespace okta_aspnetcore_mvc_example.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        private readonly IConfiguration _config;
        private readonly IViewRenderService _viewRenderService;
        private readonly IEmailService _emailService;
        //public List<AppLink> _userAppList = null;
        public UserProfileModel _userProfileModel;

        public HomeController(ILogger<HomeController> logger, IConfiguration config, IViewRenderService viewRenderService, IEmailService emailService)
        {
            _logger = logger;
            _config = config;
            _viewRenderService = viewRenderService;
            _emailService = emailService;
            _userProfileModel = new UserProfileModel();
            //_userProfileModel.listAssignedApps = new List<AppLink>();
            //_userProfileModel.listPermissions = new List<PermissionModel>();
            //_userProfileModel.listDelegates = new List<DelegateModel>();
            //_userProfileModel.listScopedConsent = new List<ScopeConsentModel>();
        }


        public IActionResult Index()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userProfileModel = GetAppsUserData();
            }

            TempData["IsRsp"] = false;
            return View(_userProfileModel);
        }

        public IActionResult About()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userProfileModel = GetAppsUserData();
            }

            TempData["IsRsp"] = false;
            return View(_userProfileModel);
        }


        //[Authorize]
        //public ActionResult Login()
        //{
        //    ViewBag.Message = "Global Login";

        //    if (!HttpContext.User.Identity.IsAuthenticated)
        //    {
        //        var properties = new AuthenticationProperties();
        //        //without this, the redirect defaults to entry point of initialization
        //        //properties.RedirectUri = "/Home/PostLogOut";
        //        return Challenge(properties, OktaDefaults.MvcAuthenticationScheme);
        //    }
        //    return RedirectToAction("Index", "Home");
        //    //return RedirectToAction("PostLogin", "Home");
        //}


        public ActionResult Login()
        {
            ViewBag.Message = "Login";

            if (HttpContext.User.Identity.IsAuthenticated)
            {
                //_userProfileModel.assignedApps = GetUserApps();
                //_userProfileModel.unassignedApps = GetAllApps();
                _userProfileModel = GetAppsUserData();
            }

            //TempData["redirectUri"] = "https://localhost:44306/Home/Login";
            //return View("../Account/authnLogin",_userProfileModel);

            //return View("../Account/oidcAuthCodeLogin", _userProfileModel);

            //return View("../Account/oidcImplicitLogin", _userProfileModel);

            //return View("../Account/oidcSignInWithSessionToken", _userProfileModel);

            return RedirectToAction("SignInRemote", "Account");
        }



        [HttpPost]
        public async Task<IActionResult> ImplicitLanding(string accessToken, string idToken)
        {
            System.Security.Claims.ClaimsPrincipal claimPrincipal = null;

            Microsoft.IdentityModel.Tokens.TokenValidationParameters validationParameters =
                new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateIssuerSigningKey = false,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false
                };

            System.IdentityModel.Tokens.Jwt.JwtSecurityToken jwtSecurityToken;
            System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();

            jwtSecurityToken = handler.ReadJwtToken(idToken);
            List<System.Security.Claims.Claim> claims = jwtSecurityToken.Claims.ToList();
            //claims.Add(new Claim("idToken", idToken));
            //claims.Add(new Claim("accessToken", accessToken));

            var claimsIdentity = new ClaimsIdentity(
                claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var authProperties = new AuthenticationProperties
            {
                //AllowRefresh = <bool>,
                // Refreshing the authentication session should be allowed.

                //ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                // The time at which the authentication ticket expires. A 
                // value set here overrides the ExpireTimeSpan option of 
                // CookieAuthenticationOptions set with AddCookie.

                //IsPersistent = true,
                // Whether the authentication session is persisted across 
                // multiple requests. When used with cookies, controls
                // whether the cookie's lifetime is absolute (matching the
                // lifetime of the authentication ticket) or session-based.

                //IssuedUtc = <DateTimeOffset>,
                // The time at which the authentication ticket was issued.

                //RedirectUri = <string>
                // The full path or absolute URI to be used as an http 
                // redirect response value.
            };

            List<AuthenticationToken> authTokens = new List<AuthenticationToken>();
            AuthenticationToken myToken = new AuthenticationToken() { Name = "id_token", Value = idToken };
            authTokens.Add(myToken);
            AuthenticationToken myAccessToken = new AuthenticationToken() { Name = "access_token", Value = accessToken };
            authTokens.Add(myAccessToken);



            authProperties.StoreTokens(authTokens);

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);


            return RedirectToAction("Index", "Home");
            //return View();
        }



        //[HttpPost]
        //public ActionResult Logout()
        //{
        //    return new SignOutResult(
        //        new[]
        //        {
        //             OktaDefaults.MvcAuthenticationScheme,
        //             CookieAuthenticationDefaults.AuthenticationScheme,
        //        },
        //       new AuthenticationProperties { RedirectUri = "/Home/Index" });
        //    //new AuthenticationProperties { RedirectUri = "/Home/PostLogOut" });
        //}

        public IActionResult ResourceOne()
        {
            TempData["IsProgressive"] = false;
            if (HttpContext.Session.GetString("firstname") == null)
            {
                TempData["IsProgressive"] = true;
                
            }
                       
            TempData["firstname"] = HttpContext.Session.GetString("firstname");           
            return View();
        }

        [HttpPost]
        public IActionResult ResourceOneRoute([FromForm]string firstname, string lastname, string getConsent)
        {
            TempData["IsProgressive"] = false;
            HttpContext.Session.SetString("firstname", firstname);
            HttpContext.Session.SetString("lastname", lastname);
            HttpContext.Session.SetString("getConsent", getConsent);
            TempData["firstname"] = firstname;
            return View("ResourceOne");
        }

        public IActionResult ResourceTwo()
        {

            TempData["IsProgressive"] = false;
            if (HttpContext.Session.GetString("region") == null)
            {
                TempData["IsProgressive"] = true;
            }

            TempData["firstname"] = HttpContext.Session.GetString("firstname");
            return View();
        }

        [HttpPost]
        public IActionResult ResourceTwoRoute([FromForm] string region)
        {

            HttpContext.Session.SetString("region", region);

            TempData["IsProgressive"] = false;
            TempData["firstname"] = HttpContext.Session.GetString("firstname");
            return View("ResourceTwo");
        }

        public IActionResult ResourceThree()
        {

            TempData["IsRegister"] = true;
 


            TempData["IsProgressive"] = false;
            if (HttpContext.Session.GetString("streetAddress") == null)
            {
                TempData["IsProgressive"] = true;
                TempData["IsRegister"] = false;
            }
            else
            {
                TempData["IsRegister"] = true;

                if (HttpContext.Session.GetString("submitRegistration") != null)
                {
                    TempData["IsRegister"] = false;
                }


            }




            TempData["firstname"] = HttpContext.Session.GetString("firstname");
            return View();
        }

        [HttpPost]
        public IActionResult ResourceThreeRoute([FromForm] string streetAddress, string city, string state, string zipCode, string insuranceCarrier, string insuranceId)
        {

            HttpContext.Session.SetString("streetAddress", streetAddress);
            HttpContext.Session.SetString("city", city);
            HttpContext.Session.SetString("state", state);
            HttpContext.Session.SetString("zipCode", zipCode);
            HttpContext.Session.SetString("insuranceCarrier", insuranceCarrier);
            HttpContext.Session.SetString("insuranceId", insuranceId);

            TempData["IsProgressive"] = false;
            TempData["IsRegister"] = true;
            TempData["firstname"] = HttpContext.Session.GetString("firstname");
            return View("ResourceThree");
        }

        [HttpPost]
        public ActionResult ProgressiveRegister([FromForm] string email, string password)
        {

            RegisterUserModel newUser = new RegisterUserModel();
            newUser.email = email;
            newUser.password = password;
            newUser.firstName = HttpContext.Session.GetString("firstname");
            newUser.lastName = HttpContext.Session.GetString("lastname");
            newUser.region = HttpContext.Session.GetString("region");
            newUser.streetAddress = HttpContext.Session.GetString("streetAddress");
            newUser.city = HttpContext.Session.GetString("city");
            newUser.state = HttpContext.Session.GetString("state");
            newUser.zipCode = HttpContext.Session.GetString("zipCode");
            newUser.insuranceCarrier = HttpContext.Session.GetString("insuranceCarrier");
            newUser.insuranceId = HttpContext.Session.GetString("insuranceId");


            var destPage = _config.GetValue<string>("SendApi:RegistrationFlo");
            string consentToken = _config.GetValue<string>("SendApi:RegistrationToken");
            IRestResponse response = null;


            var client = new RestClient(destPage);
            var request = new RestRequest(Method.POST);
            // request.AddHeader("cache-control", "no-cache");
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("x-api-client-token", consentToken);
            request.AddJsonBody(newUser);
            response = client.Execute(request);


            if (response.StatusDescription == "Forbidden" || response.StatusDescription == "Unauthorized")
            {

            }


            if (response.StatusDescription == "OK")
            {
                TempData["IsRegister"] = false;

                HttpContext.Session.SetString("submitRegistration", "true");
            }
            else
            {
                TempData["IsRegister"] = true;
                HttpContext.Session.SetString("submitRegistration", "false");
            }



            TempData["IsProgressive"] = false;
            
            TempData["firstname"] = HttpContext.Session.GetString("firstname");
            return View("ResourceThree");

        }



        public ActionResult Register()
        {
            ViewBag.Message = "Registration Page.";


            TempData["IsRsp"] = false;
            return View();
            //return RedirectToAction("Index", "Home");
            //return RedirectToAction("PostLogin", "Home");
        }

        [HttpPost]
        public ActionResult RegisterRoute([FromForm] RegisterUserModel newUser)
        {

            //UserProfile userProfile = new UserProfile
            //{
            //    FirstName = newUser.firstName,
            //    LastName = newUser.lastName,
            //    Email = newUser.email,
            //    Login = newUser.email
            //};

            //Okta.Sdk.IUser oktaUser = null;

            //var client = new OktaClient(new OktaClientConfiguration
            //{
            //    OktaDomain = _config.GetValue<string>("OktaWeb:OktaDomain"),
            //    Token = _config.GetValue<string>("OktaWeb:ApiToken")
            //});


            //// Create a user with the specified password
            //oktaUser = await client.Users.CreateUserAsync(new CreateUserWithPasswordOptions
            //{
            //    // User profile object
            //    Profile = userProfile,
            //    Password = newuser.password,
            //    Activate = false,
            //});

            //oktaUser.Profile["customId"] = newuser.customId;
            //await oktaUser.UpdateAsync();

            var destPage = _config.GetValue<string>("SendApi:RegistrationFlo");
            string consentToken = _config.GetValue<string>("SendApi:RegistrationToken");
            IRestResponse response = null;


            var client = new RestClient(destPage);
            var request = new RestRequest(Method.POST);
            // request.AddHeader("cache-control", "no-cache");
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("x-api-client-token", consentToken);
            request.AddJsonBody(newUser);
            response = client.Execute(request);


            if (response.StatusDescription == "Forbidden" || response.StatusDescription == "Unauthorized")
            {

            }


            if (response.StatusDescription == "OK")
            {

            }
            else
            {

            }


            //return View("PostRegister");


            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userProfileModel = GetAppsUserData();
            }

            TempData["IsRsp"] = true;
            TempData["title"] = "Registration Submitted";
            TempData["message1"] = "Please Check your email for Acceptance.";
            TempData["message2"] = "Note: External Account Validation can take 3 Days";
            return View("Index", _userProfileModel);


        }

        //[Authorize]
        //public ActionResult PostLogin()
        //{
        //    if (HttpContext.User.Identity.IsAuthenticated)
        //    {
        //        //_userProfileModel.assignedApps = GetUserApps();
        //        //_userProfileModel.unassignedApps = GetAllApps();
        //        _userProfileModel = GetAppsUserData();
        //    }
        //    return View(_userProfileModel);
        //    //return View();
        //}

        //public ActionResult PostLogOut()
        //{
        //    if (HttpContext.User.Identity.IsAuthenticated)
        //    {
        //        //_userProfileModel.assignedApps = GetUserApps();
        //        //_userProfileModel.unassignedApps = GetAllApps();
        //        _userProfileModel = GetAppsUserData();
        //    }
        //    return View(_userProfileModel);
        //    //return View();
        //}


        public UserProfileModel GetAppsUserData()
        {
            UserProfileModel myAppProfile = new UserProfileModel();
            myAppProfile.unassignedApps = new List<string>();
            myAppProfile.listAssignedApps = new List<AppLink>();
            Okta.Sdk.User oktaUser = null;
            myAppProfile.listCustodians = new List<PresentUserModel>();
            myAppProfile.listDependants = new List<PresentUserModel>();
            myAppProfile.listPermissions = new List<PresentUserModel>();
            myAppProfile.listDelegates = new List<PresentUserModel>();
            myAppProfile.listScopedConsent = new List<ScopeConsentModel>();
            //ListPermissionModel myPermissions = new ListPermissionModel();
            //ListDelegateModel myDelegates = new ListDelegateModel();

            var client = new OktaClient(new OktaClientConfiguration
            {
                OktaDomain = _config.GetValue<string>("OktaWeb:OktaDomain"),
                Token = _config.GetValue<string>("OktaWeb:ApiToken")
            });

            /// get apps assigned to user
            var oktaId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;
            oktaUser = (Okta.Sdk.User)client.Users.GetUserAsync(oktaId).Result;

            var sortingList = new List<string>();

            var listAssignedApps = client.Users.ListAppLinks(oktaId, showAll: false).ToListAsync().Result;
            foreach (var item in listAssignedApps)
            {
                if (item.Label.IndexOf("CVS Home") < 0)
                {
                    myAppProfile.listAssignedApps.Add((AppLink)item);
                    
                }
                sortingList.Add(item.Label);
            }

            var listAllApps = client.Applications.ListApplications().ToListAsync().Result;
            foreach (var item in listAllApps)
            {
                var temp1 = item.Label.IndexOf("CVS");
                if (item.Label.IndexOf("CVS") == 0)
                {
                    if(!sortingList.Contains(item.Label))
                    {
                        //var temp = item.Label;
                        //allAppList.Add(item.Label);
                        myAppProfile.unassignedApps.Add(item.Label);
                    }
                }
            }


            //get list of current delegates
            if (this.User.Claims.FirstOrDefault(x => x.Type == "peopleIhaveDelegated") != null)
            {
                var tempDelegates = this.User.Claims.Where(x => x.Type == "peopleIhaveDelegated").Where(p => p.Issuer != "OpenIdConnect").ToList();
                foreach (var item in tempDelegates)
                {
                    PresentUserModel myDelegates = new PresentUserModel();
                    //value == oktaid, perform lookup and get addl data
                    oktaUser = (Okta.Sdk.User)client.Users.GetUserAsync(item.Value).Result;
                    myDelegates.oktaId = item.Value;
                    myDelegates.email = oktaUser.Profile.Email;
                    myDelegates.userName = oktaUser.Profile.LastName;
                    myAppProfile.listDelegates.Add(myDelegates);
                }
            }

            //get list of current permissions
            if (this.User.Claims.FirstOrDefault(x => x.Type == "peopleIhavePermissionOver") != null)
            {
                var tempPermissions = this.User.Claims.Where(x => x.Type == "peopleIhavePermissionOver").Where(p => p.Issuer != "OpenIdConnect").ToList();
                foreach (var item in tempPermissions)
                {
                    PresentUserModel myPermissions = new PresentUserModel();
                    //value == oktaid, perform lookup and get addl data
                    oktaUser = (Okta.Sdk.User)client.Users.GetUserAsync(item.Value).Result;
                    myPermissions.oktaId = item.Value;
                    myPermissions.email = oktaUser.Profile.Email;
                    myPermissions.userName = oktaUser.Profile.LastName;


                    myAppProfile.listPermissions.Add(myPermissions);
                }
            }

            //get list of current dependants
            if (this.User.Claims.FirstOrDefault(x => x.Type == "myDependants") != null)
            {
                var tempDependants = this.User.Claims.Where(x => x.Type == "myDependants").Where(p => p.Issuer != "OpenIdConnect").ToList();
                foreach (var item in tempDependants)
                {
                    PresentUserModel myDependants = new PresentUserModel();
                    //value == oktaid, perform lookup and get addl data
                    oktaUser = (Okta.Sdk.User)client.Users.GetUserAsync(item.Value).Result;
                    myDependants.oktaId = item.Value;
                    myDependants.email = oktaUser.Profile.Email;
                    myDependants.userName = oktaUser.Profile.LastName;
                    myAppProfile.listDependants.Add(myDependants);
                }
            }

            //get list of current custodians
            if (this.User.Claims.FirstOrDefault(x => x.Type == "myCustodians") != null)
            {
                var tempCustodians = this.User.Claims.Where(x => x.Type == "myCustodians").Where(p => p.Issuer != "OpenIdConnect").ToList();
                foreach (var item in tempCustodians)
                {
                    PresentUserModel myCustodians = new PresentUserModel();
                    //value == oktaid, perform lookup and get addl data
                    oktaUser = (Okta.Sdk.User)client.Users.GetUserAsync(item.Value).Result;
                    myCustodians.oktaId = item.Value;
                    myCustodians.email = oktaUser.Profile.Email;
                    myCustodians.userName = oktaUser.Profile.LastName;

                    myAppProfile.listCustodians.Add(myCustodians);
                }
            }

            return myAppProfile;
        }



        public List<string> GetAllApps()
        {
 
            List<string> allAppList = new List<string>();

            var client = new OktaClient(new OktaClientConfiguration
            {
                OktaDomain = _config.GetValue<string>("OktaWeb:OktaDomain"),
                Token = _config.GetValue<string>("OktaWeb:ApiToken")
            });



            var myList = client.Applications.ListApplications().ToListAsync().Result;
            //var myList = client.Users.ListAppLinks(oktaId, showAll: true).ToListAsync().Result;
            foreach (var item in myList)
            {
                var temp1 = item.Label.IndexOf("CVS");
                if (item.Label.IndexOf("CVS") == 0)
                {
                    //var temp = item.Label;
                    allAppList.Add(item.Label);
                }

            }

            return allAppList;
        }

        public List<AppLink> GetUserApps()
        {
            Okta.Sdk.User oktaUser = null;
            List<AppLink> userAppList = new List<AppLink>();

            var client = new OktaClient(new OktaClientConfiguration
            {
                OktaDomain = _config.GetValue<string>("OktaWeb:OktaDomain"),
                Token = _config.GetValue<string>("OktaWeb:ApiToken")
            });

            var oktaId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;



            //oktaUser = (Okta.Sdk.User)client.Users.GetUserAsync(oktaId).Result;

            //string userId = oktaUser.Id;

            //var myResource = client.GetAsync<Okta.Sdk.Resource>(new Okta.Sdk.HttpRequest
            //{
            //    Uri = $"/api/v1/users/{userId}/appLinks",
            //    PathParameters = new Dictionary<string, object>()
            //    {
            //        ["userId"] = oktaId,
            //    }
            //});

            ////Okta.Sdk.IResource;

            //CollectionClient<Okta.Sdk.IResource> myCol = client.GetCollection<Okta.Sdk.IResource>(new Okta.Sdk.HttpRequest
            //{
            //    Uri = $"/api/v1/users/{userId}/appLinks",
            //    PathParameters = new Dictionary<string, object>()
            //    {
            //        ["userId"] = oktaId,
            //    }
            //});


            var myList = client.Users.ListAppLinks(oktaId, showAll: false).ToListAsync().Result;
            foreach (var item in myList)
            {
                if (item.Label.IndexOf("CVS Home") < 0)
                {
                    userAppList.Add((AppLink)item);
                }

            }

            return userAppList;
        }


        [HttpGet]
        [Authorize]
        public ActionResult AssignApp([FromQuery] string requestLabel)
        {

            var temp = requestLabel;

            //call Workflows to add user to Group for provisioning and SSO

            var destPage = _config.GetValue<string>("SendApi:AssignAppFlo");
            string consentToken = _config.GetValue<string>("SendApi:AssignAppToken");
            IRestResponse response = null;

            RequestAppModel requestAppModel = new RequestAppModel();
            requestAppModel.oktaId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;
            requestAppModel.appName = requestLabel;
            requestAppModel.email = this.User.Claims.FirstOrDefault(x => x.Type == "email").Value;


            var client = new RestClient(destPage);
            var request = new RestRequest(Method.POST);
            // request.AddHeader("cache-control", "no-cache");
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("x-api-client-token", consentToken);
            request.AddJsonBody(requestAppModel);
            response = client.Execute(request);


            if (response.StatusDescription == "Forbidden" || response.StatusDescription == "Unauthorized")
            {

            }


            if (response.StatusDescription == "OK")
            {

            }
            else
            {

            }



            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userProfileModel = GetAppsUserData();
            }

            TempData["IsRsp"] = true;
            TempData["title"] = "Application Request Received";
            TempData["message1"] = "Please Refresh to See All Apps.";
            TempData["message2"] = "Note: It may take a moment...";
            return View("Index", _userProfileModel);

        }



        [HttpGet]
        [Authorize]
        public ActionResult RequestApp()
        {

            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userProfileModel = GetAppsUserData();
            }

            TempData["IsRsp"] = false;
            return View("RequestApp", _userProfileModel);
        }


        [HttpPost]
        [Authorize]
        public ActionResult RequestAppRoute(string requestApp)
        {

            var destPage = _config.GetValue<string>("SendApi:RequestAppFlo");
            string consentToken = _config.GetValue<string>("SendApi:RequestAppToken");
            IRestResponse response = null;

            RequestAppModel requestAppModel = new RequestAppModel();
            requestAppModel.oktaId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;
            requestAppModel.appName = requestApp;
            requestAppModel.email = this.User.Claims.FirstOrDefault(x => x.Type == "email").Value;


            var client = new RestClient(destPage);
            var request = new RestRequest(Method.POST);
            // request.AddHeader("cache-control", "no-cache");
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("x-api-client-token", consentToken);
            request.AddJsonBody(requestAppModel);
            response = client.Execute(request);


            if (response.StatusDescription == "Forbidden" || response.StatusDescription == "Unauthorized")
            {

            }


            if (response.StatusDescription == "OK")
            {

            }
            else
            {

            }

            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userProfileModel = GetAppsUserData();
            }

            TempData["IsRsp"] = true;
            TempData["title"] = "Application Request Submitted";
            TempData["message1"] = "Please Check your email for Acceptance.";
            TempData["message2"] = "Note: Requests can take up to 3 days";
            return View("Index", _userProfileModel);

        }

        [HttpGet]
        [Authorize]
        public ActionResult ManageDependant()
        {

            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userProfileModel = GetAppsUserData();
            }

            TempData["IsRsp"] = false;

            return View(_userProfileModel);
        }

        [HttpPost]
        [Authorize]
        public ActionResult AddDependantRoute(string searchCriteria)
        {

            var destPage = _config.GetValue<string>("SendApi:AddDependantFlo");
            string consentToken = _config.GetValue<string>("SendApi:AddDependantToken");
            IRestResponse response = null;

            LinkedUserModel dependantUserModel = new LinkedUserModel();
            dependantUserModel.parentOktaId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;
            dependantUserModel.searchCriteria = searchCriteria;
            dependantUserModel.parentEmail = this.User.Claims.FirstOrDefault(x => x.Type == "email").Value;


            var client = new RestClient(destPage);
            var request = new RestRequest(Method.POST);
            // request.AddHeader("cache-control", "no-cache");
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("x-api-client-token", consentToken);
            request.AddJsonBody(dependantUserModel);
            response = client.Execute(request);


            if (response.StatusDescription == "Forbidden" || response.StatusDescription == "Unauthorized")
            {

            }


            if (response.StatusDescription == "OK")
            {

            }
            else
            {

            }

            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userProfileModel = GetAppsUserData();
            }

            TempData["IsRsp"] = true;
            TempData["title"] = "Dependants";
            TempData["message1"] = "Your Request to Add a Dependant has been Submitted";
            TempData["message2"] = "Please Check your email for Confirmation.";
            return View("Index", _userProfileModel);
        }


        [HttpPost]
        [Authorize]
        public ActionResult RemoveDependantRoute(string dependantEmail, string dependantOktaId)
        {

            var destPage = _config.GetValue<string>("SendApi:RemoveDependantFlo");
            string consentToken = _config.GetValue<string>("SendApi:RemoveDependantToken");
            IRestResponse response = null;

            LinkedUserModel dependantUserModel = new LinkedUserModel();
            dependantUserModel.parentOktaId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;
            dependantUserModel.parentEmail = this.User.Claims.FirstOrDefault(x => x.Type == "email").Value;
            dependantUserModel.childOktaId = dependantOktaId;
            dependantUserModel.childEmail = dependantEmail;


            var client = new RestClient(destPage);
            var request = new RestRequest(Method.POST);
            // request.AddHeader("cache-control", "no-cache");
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("x-api-client-token", consentToken);
            request.AddJsonBody(dependantUserModel);
            response = client.Execute(request);


            if (response.StatusDescription == "Forbidden" || response.StatusDescription == "Unauthorized")
            {

            }


            if (response.StatusDescription == "OK")
            {

            }
            else
            {

            }

            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userProfileModel = GetAppsUserData();
            }

            TempData["IsRsp"] = true;
            TempData["title"] = "Dependants";
            TempData["message1"] = "Your have Removed a Dependant from your account";
            TempData["message2"] = "";
            return View("Index", _userProfileModel);
        }


        [HttpPost]
        [Authorize]
        public ActionResult ViewDependantRoute(string dependantEmail, string dependantOktaId)
        {

            //prior to allowing profile update
            //require additional factor, Email MFA

            //?? different profile for consumer and provider ??

            //display current profile
            Okta.Sdk.User oktaUser = null;


            var client = new OktaClient(new OktaClientConfiguration
            {
                OktaDomain = _config.GetValue<string>("OktaWeb:OktaDomain"),
                Token = _config.GetValue<string>("OktaWeb:ApiToken")
            });

            //var oktaId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;

            _userProfileModel = GetAppsUserData();

            oktaUser = (Okta.Sdk.User)client.Users.GetUserAsync(dependantOktaId).Result;

            //common attributes
            if (oktaUser.Profile.Email != null) { _userProfileModel.email = oktaUser.Profile.Email; }
            if (oktaUser.Profile.FirstName != null) { _userProfileModel.firstName = oktaUser.Profile.FirstName; }
            if (oktaUser.Profile.LastName != null) { _userProfileModel.lastName = oktaUser.Profile.LastName; }

            //consumer attributes
            if (oktaUser.Profile["region"] != null) { _userProfileModel.region = oktaUser.Profile["region"].ToString(); }


            ////progressive consumer attributes
            if (oktaUser.Profile["streetAddress"] != null) { _userProfileModel.streetAddress = oktaUser.Profile["streetAddress"].ToString(); }
            if (oktaUser.Profile["city"] != null) { _userProfileModel.city = oktaUser.Profile["city"].ToString(); }
            if (oktaUser.Profile["state"] != null) { _userProfileModel.state = oktaUser.Profile["state"].ToString(); }
            if (oktaUser.Profile["zipCode"] != null) { _userProfileModel.zipCode = oktaUser.Profile["zipCode"].ToString(); }


            //provider attributes
            if (oktaUser.Profile["licenseState"] != null) { _userProfileModel.licenseState = oktaUser.Profile["licenseState"].ToString(); }
            if (oktaUser.Profile["physicianId"] != null) { _userProfileModel.physicianId = oktaUser.Profile["physicianId"].ToString(); }
            if (oktaUser.Profile["practiceName"] != null) { _userProfileModel.practiceName = oktaUser.Profile["practiceName"].ToString(); }

            //preferences
            if (oktaUser.Profile["Promotions"] != null) { _userProfileModel.Promotions = (bool)oktaUser.Profile["Promotions"]; }
            if (oktaUser.Profile["ProductUpdates"] != null) { _userProfileModel.ProductUpdates = (bool)oktaUser.Profile["ProductUpdates"]; }
            if (oktaUser.Profile["Webinars"] != null) { _userProfileModel.Webinars = (bool)oktaUser.Profile["Webinars"]; }


            //consent
            if (oktaUser.Profile["last_verification_date"] != null) { _userProfileModel.last_verification_date = oktaUser.Profile["last_verification_date"].ToString(); }
            if (oktaUser.Profile["consent"] != null) { _userProfileModel.consent = oktaUser.Profile["consent"].ToString(); }

            //misc
            //if (oktaUser.Profile["level_of_assurance"] != null) { _userProfileModel.level_of_assurance = oktaUser.Profile["level_of_assurance"].ToString(); }
            //if (oktaUser.Profile["primaryRole"] != null) { _userProfileModel.primaryRole = oktaUser.Profile["primaryRole"].ToString(); }
            _userProfileModel.oktaId = dependantOktaId;
            _userProfileModel.auth_idp = "00o31h3h8X1Rmi47z1d6";

            if (oktaUser.Profile.Email != null) { _userProfileModel.email = oktaUser.Profile.Email; }
            if (oktaUser.Profile.FirstName != null) { _userProfileModel.firstName = oktaUser.Profile.FirstName; }
            if (oktaUser.Profile.LastName != null) { _userProfileModel.lastName = oktaUser.Profile.LastName; }





            TempData["IsRsp"] = false;
            //return View("Account", _userProfileModel);
            return View("Profile", _userProfileModel);
        }



        [HttpGet]
        [Authorize]
        public ActionResult ManageDelegate()
        {

            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userProfileModel = GetAppsUserData();
            }

            TempData["IsRsp"] = false;
            return View(_userProfileModel);
        }

        [HttpPost]
        [Authorize]
        public ActionResult AddDelegateRoute(string searchCriteria)
        {

            var destPage = _config.GetValue<string>("SendApi:AddDelegateFlo");
            string consentToken = _config.GetValue<string>("SendApi:AddDelegateToken");
            IRestResponse response = null;

            LinkedUserModel delegateUserModel = new LinkedUserModel();
            delegateUserModel.parentOktaId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;
            delegateUserModel.searchCriteria = searchCriteria;
            delegateUserModel.parentEmail = this.User.Claims.FirstOrDefault(x => x.Type == "email").Value;


            var client = new RestClient(destPage);
            var request = new RestRequest(Method.POST);
            // request.AddHeader("cache-control", "no-cache");
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("x-api-client-token", consentToken);
            request.AddJsonBody(delegateUserModel);
            response = client.Execute(request);


            if (response.StatusDescription == "Forbidden" || response.StatusDescription == "Unauthorized")
            {

            }


            if (response.StatusDescription == "OK")
            {

            }
            else
            {

            }

            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userProfileModel = GetAppsUserData();
            }

            TempData["IsRsp"] = true;
            TempData["title"] = "Delegate Permissions";
            TempData["message1"] = "Your Request to Delegate Permissions has been Submitted";
            TempData["message2"] = "Please Check your email for Confirmation.";
            return View("Index", _userProfileModel);
        }


        [HttpPost]
        [Authorize]
        public ActionResult RemoveDelegateRoute(string delegateEmail, string delegateOktaId)
        {

            var destPage = _config.GetValue<string>("SendApi:RemoveDelegateFlo");
            string consentToken = _config.GetValue<string>("SendApi:RemoveDelegateToken");
            IRestResponse response = null;

            LinkedUserModel delegateUserModel = new LinkedUserModel();
            delegateUserModel.parentOktaId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;
            delegateUserModel.parentEmail = this.User.Claims.FirstOrDefault(x => x.Type == "email").Value;
            delegateUserModel.childOktaId = delegateOktaId;
            delegateUserModel.childEmail = delegateEmail;


            var client = new RestClient(destPage);
            var request = new RestRequest(Method.POST);
            // request.AddHeader("cache-control", "no-cache");
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("x-api-client-token", consentToken);
            request.AddJsonBody(delegateUserModel);
            response = client.Execute(request);


            if (response.StatusDescription == "Forbidden" || response.StatusDescription == "Unauthorized")
            {

            }


            if (response.StatusDescription == "OK")
            {

            }
            else
            {

            }

            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userProfileModel = GetAppsUserData();
            }

            TempData["IsRsp"] = true;
            TempData["title"] = "Delegate Permissions";
            TempData["message1"] = "Your have Remove a  Delegate from your account";
            TempData["message2"] = "";
            return View("Index", _userProfileModel);
        }

        [HttpPost]
        [Authorize]
        public ActionResult ViewDelegateRoute(string delegateEmail, string delegateOktaId)
        {

            //prior to allowing profile update
            //require additional factor, Email MFA

            //?? different profile for consumer and provider ??

            //display current profile
            Okta.Sdk.User oktaUser = null;


            var client = new OktaClient(new OktaClientConfiguration
            {
                OktaDomain = _config.GetValue<string>("OktaWeb:OktaDomain"),
                Token = _config.GetValue<string>("OktaWeb:ApiToken")
            });

            //var oktaId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;

            _userProfileModel = GetAppsUserData();

            oktaUser = (Okta.Sdk.User)client.Users.GetUserAsync(delegateOktaId).Result;

            //common attributes
            if (oktaUser.Profile.Email != null) { _userProfileModel.email = oktaUser.Profile.Email; }
            if (oktaUser.Profile.FirstName != null) { _userProfileModel.firstName = oktaUser.Profile.FirstName; }
            if (oktaUser.Profile.LastName != null) { _userProfileModel.lastName = oktaUser.Profile.LastName; }

            //consumer attributes
            if (oktaUser.Profile["region"] != null) { _userProfileModel.region = oktaUser.Profile["region"].ToString(); }


            ////progressive consumer attributes
            if (oktaUser.Profile["streetAddress"] != null) { _userProfileModel.streetAddress = oktaUser.Profile["streetAddress"].ToString(); }
            if (oktaUser.Profile["city"] != null) { _userProfileModel.city = oktaUser.Profile["city"].ToString(); }
            if (oktaUser.Profile["state"] != null) { _userProfileModel.state = oktaUser.Profile["state"].ToString(); }
            if (oktaUser.Profile["zipCode"] != null) { _userProfileModel.zipCode = oktaUser.Profile["zipCode"].ToString(); }


            //provider attributes
            if (oktaUser.Profile["licenseState"] != null) { _userProfileModel.licenseState = oktaUser.Profile["licenseState"].ToString(); }
            if (oktaUser.Profile["physicianId"] != null) { _userProfileModel.physicianId = oktaUser.Profile["physicianId"].ToString(); }
            if (oktaUser.Profile["practiceName"] != null) { _userProfileModel.practiceName = oktaUser.Profile["practiceName"].ToString(); }

            //preferences
            if (oktaUser.Profile["Promotions"] != null) { _userProfileModel.Promotions = (bool)oktaUser.Profile["Promotions"]; }
            if (oktaUser.Profile["ProductUpdates"] != null) { _userProfileModel.ProductUpdates = (bool)oktaUser.Profile["ProductUpdates"]; }
            if (oktaUser.Profile["Webinars"] != null) { _userProfileModel.Webinars = (bool)oktaUser.Profile["Webinars"]; }


            //consent
            if (oktaUser.Profile["last_verification_date"] != null) { _userProfileModel.last_verification_date = oktaUser.Profile["last_verification_date"].ToString(); }
            if (oktaUser.Profile["consent"] != null) { _userProfileModel.consent = oktaUser.Profile["consent"].ToString(); }

            //misc
            //if (oktaUser.Profile["level_of_assurance"] != null) { _userProfileModel.level_of_assurance = oktaUser.Profile["level_of_assurance"].ToString(); }
            //if (oktaUser.Profile["primaryRole"] != null) { _userProfileModel.primaryRole = oktaUser.Profile["primaryRole"].ToString(); }
            _userProfileModel.oktaId = delegateOktaId;
            _userProfileModel.auth_idp = "00o31h3h8X1Rmi47z1d6";

            if (oktaUser.Profile.Email != null) { _userProfileModel.email = oktaUser.Profile.Email; }
            if (oktaUser.Profile.FirstName != null) { _userProfileModel.firstName = oktaUser.Profile.FirstName; }
            if (oktaUser.Profile.LastName != null) { _userProfileModel.lastName = oktaUser.Profile.LastName; }





            TempData["IsRsp"] = false;
            //return View("Account", _userProfileModel);
            return View("Profile", _userProfileModel);
        }



        //[HttpGet]
        //public ActionResult RequestReply(string token, string locator)
        //{

        //    ProcessRequestReply(token, locator);

        //    return View("RequestReply");
        //    //return RedirectToAction("Index", "Home");
        //}



        //public string ProcessRequestReply(string token, string oktaId)
        //{
        //    Okta.Sdk.User oktaUser = null;

        //    var client = new OktaClient(new OktaClientConfiguration
        //    {
        //        OktaDomain = _config.GetValue<string>("OktaWeb:OktaDomain"),
        //        Token = _config.GetValue<string>("OktaWeb:ApiToken")
        //    });

        //    if (string.IsNullOrEmpty(token) && TempData["token"] != null)
        //    {
        //        token = TempData["token"].ToString();
        //    }

        //    if (oktaId != null)
        //    {
        //        //get user to ensure state
        //        oktaUser = (Okta.Sdk.User)client.Users.GetUserAsync(oktaId).Result;

        //        if (token == "123456")
        //        {
        //            //add user to group
        //            var group = client.Groups.FirstOrDefaultAsync(x => x.Profile.Name == "OIDC_users").Result;
        //            if (group != null && oktaUser != null)
        //            {
        //                client.Groups.AddUserToGroupAsync(group.Id, oktaUser.Id); ;
        //            }



        //            //send approval notice email
        //            var basePath = $"{Request.Scheme}://{Request.Host}";
        //            EmailViewModel emailViewModel = new EmailViewModel
        //            {
        //                OktaId = oktaUser.Id,
        //                Name = string.Format("{0} {1}", oktaUser.Profile.FirstName, oktaUser.Profile.LastName),
        //                LinkExpiry = "72",
        //                AcceptToken = "123456",
        //                RejectToken = "987654",
        //                BasePath = basePath
        //            };
        //            var result = _viewRenderService.RenderToStringAsync("Shared/_AccessGranted", emailViewModel).Result;
        //            var isSuccess = _emailService.SendEmail("admin@aclarkesylvania.com", oktaUser.Profile.Email , "Application Access Approved", result);

        //        }
        //        else
        //        {
        //            //send reject notice email
        //            var basePath = $"{Request.Scheme}://{Request.Host}";
        //            EmailViewModel emailViewModel = new EmailViewModel
        //            {
        //                OktaId = oktaUser.Id,
        //                Name = string.Format("{0} {1}", oktaUser.Profile.FirstName, oktaUser.Profile.LastName),
        //                LinkExpiry = "72",
        //                AcceptToken = "123456",
        //                RejectToken = "987654",
        //                BasePath = basePath
        //            };
        //            var result = _viewRenderService.RenderToStringAsync("Shared/_AccessRejected", emailViewModel).Result;
        //            var isSuccess = _emailService.SendEmail("admin@aclarkesylvania.com", oktaUser.Profile.Email, "Application Access Rejected", result);

        //        }

        //        return "success";
        //    }
        //    else
        //    {
        //        return "failed";
        //    }
        //}


        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [Authorize]
        public IActionResult Token(string resourceServerData,string idpToken)
        {

            ApiResponseModel resourceServer = new ApiResponseModel();
            if (!string.IsNullOrEmpty(resourceServerData))
            {
                resourceServer = JsonConvert.DeserializeObject<ApiResponseModel>(resourceServerData);
            }


 
            Dictionary<string, string> idpAccessToken = new Dictionary<string, string>();
            if (!string.IsNullOrEmpty(idpToken))
            {
                var handler1 = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                var token1 = handler1.ReadJwtToken(idpToken);
                foreach (var item in token1.Payload)
                {
                    idpAccessToken.Add(item.Key, item.Value.ToString());
                }
            }



            foreach (var item in HttpContext.User.Claims)
            {
                var temp = item;
            }

            //from asp.net middleware
            var idToken = HttpContext.GetTokenAsync("id_token").Result;
            var accessToken = HttpContext.GetTokenAsync("access_token").Result;
            var refreshToken = HttpContext.GetTokenAsync("refresh_token").Result;

            var jwt = accessToken;
            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwt);
            Dictionary<string, string> myAccessClaims =  new Dictionary<string, string>();

            foreach (var item in token.Payload)
            {
                myAccessClaims.Add(item.Key, item.Value.ToString());
            }


            var userId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;
            var idpId = this.User.Claims.FirstOrDefault(x => x.Type == "idp").Value;

            myAccessClaims.Add("idpId", idpId);

            //if (HttpContext.User.Identity.IsAuthenticated)
            //{

            //    //_userProfileModel.listAssignedApps = GetUserApps();
            //    //_userProfileModel.unassignedApps = GetAllApps();
            //    _userProfileModel = GetAppsUserData();
            //}

            //TempData["IsRsp"] = false;
            //return View(_userProfileModel);
            //return View(HttpContext.User.Claims);

            ViewData["apiRsp"] = resourceServer;
            ViewData["idpRsp"] = idpAccessToken;
            return View(myAccessClaims);
        }
        
        [HttpPost]
        public IActionResult receiveIdpToken([FromForm] string id_token,string state)
        {
            Dictionary<string, string> myAccessClaims = new Dictionary<string, string>();
            string myAccessToken = null;

            var client = new OktaClient(new OktaClientConfiguration
            {
                //OktaDomain = _config.GetValue<string>("OktaWeb:OktaDomain"),
                OktaDomain = "https://cvsciam20.oktapreview.com",
                Token = _config.GetValue<string>("OktaWeb:ApiToken")
            });


            //var idpsId = "0oa5prlfuyyCWntgD1d6"
            //var userId = "00u3inrcgGfshFa1Y1d6";
            var userId = state;
            var idpsId = _config.GetValue<string>("IdpTokens:Idp");

            CollectionClient<Okta.Sdk.IResource> myCollection = client.GetCollection<Okta.Sdk.IResource>(new Okta.Sdk.HttpRequest
            {
                Uri = $"/api/v1/idps/{idpsId}/users/{userId}/credentials/tokens",
                PathParameters = new Dictionary<string, object>()
                {
                            ["userId"] = userId,
                            ["idpsId"] = idpsId
                }
            });

            var myIdpResponse = myCollection.ToListAsync().Result;
            foreach (var item in myIdpResponse)
            {
                var myData = item.GetData();
                myAccessToken = myData.FirstOrDefault(x => x.Key == "token").Value.ToString();
                //Dictionary<string, object> myLinks = (Dictionary<string, object>)myData.FirstOrDefault(x => x.Key == "_links").Value;
                //Dictionary<string, object> myScope = (Dictionary<string, object>)myLinks.FirstOrDefault(x => x.Key == "scope").Value;
                //string myTitle = myScope.FirstOrDefault(x => x.Key == "title").Value.ToString();
                //ScopeConsentModel scopeModel = new ScopeConsentModel();
                //scopeModel.scopeId = myScopeId;
                //scopeModel.scopeTitle = myTitle;
                //_userProfileModel.listScopedConsent.Add(scopeModel);
            }

            //var myResource = client.GetAsync<Okta.Sdk.Resource>(new Okta.Sdk.HttpRequest
            //{
            //    Uri = $"/api/v1/idps/{idpsId}/users/{userId}/credentials/tokens",
            //    PathParameters = new Dictionary<string, object>()
            //    {
            //        ["userId"] = userId,
            //        ["idpsId"] = idpsId
            //    }
            //}).Result;



            //return View();
            return RedirectToAction("Token", new { idpToken = myAccessToken });
        }

        public IActionResult IdpTokens()
        {
            string authServer = _config.GetValue<string>("IdpTokens:Authority");
            string clientId = _config.GetValue<string>("IdpTokens:ClientId");
            string scopes = _config.GetValue<string>("IdpTokens:Scopes");
            string redirectUri = _config.GetValue<string>("IdpTokens:RedirectUri");
            string idp = _config.GetValue<string>("IdpTokens:Idp");


            Random random = new Random();
            string nonceValue = random.Next(99999, 1000000).ToString();
            string stateCode = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;
            string oauthUrl = authServer + "/v1/authorize?idp=" + idp + "&response_type=id_token&response_mode=form_post&client_id=" + clientId + "&scope=" + scopes + "&state=" + stateCode + " &nonce=" + nonceValue + "&redirect_uri=" + redirectUri;
            //string oauthUrl = appSettings["oidc.authServer"] + "/v1/authorize?idp=0oak4qcg796eVYakY0h7&response_type=id_token token&response_mode=form_post&client_id=" + appSettings["oidc.spintweb.clientId"] + "&scope=" + appSettings["oidc.scopes"] + "&state=" + stateCode + " &nonce=" + nonceValue + "&redirect_uri=" + appSettings["oidc.spintweb.RedirectUri"] + "&sessionToken=" + mySessionToken;
            return Redirect(oauthUrl);
        }

        public IActionResult StepUpAuth()
        {
           string authServer =  _config.GetValue<string>("StepUp:Authority");
            string clientId = _config.GetValue<string>("StepUp:ClientId");
            string scopes = _config.GetValue<string>("StepUp:Scopes");
            string redirectUri = _config.GetValue<string>("StepUp:RedirectUri");


            Random random = new Random();
            string nonceValue = random.Next(99999, 1000000).ToString();
            string stateCode = "myStateInfo";
            string oauthUrl = authServer + "/v1/authorize?response_type=id_token&response_mode=form_post&client_id=" + clientId + "&scope=" + scopes + "&state=" + stateCode + " &nonce=" + nonceValue + "&redirect_uri=" + redirectUri;
            //string oauthUrl = appSettings["oidc.authServer"] + "/v1/authorize?idp=0oak4qcg796eVYakY0h7&response_type=id_token token&response_mode=form_post&client_id=" + appSettings["oidc.spintweb.clientId"] + "&scope=" + appSettings["oidc.scopes"] + "&state=" + stateCode + " &nonce=" + nonceValue + "&redirect_uri=" + appSettings["oidc.spintweb.RedirectUri"] + "&sessionToken=" + mySessionToken;
            return Redirect(oauthUrl);
        }






        [Authorize]
        public IActionResult Profile()
        {
            //prior to allowing profile update
            //require additional factor, Email MFA

            //?? different profile for consumer and provider ??

            //display current profile
            Okta.Sdk.User oktaUser = null;


            var client = new OktaClient(new OktaClientConfiguration
            {
                OktaDomain = _config.GetValue<string>("OktaWeb:OktaDomain"),
                Token = _config.GetValue<string>("OktaWeb:ApiToken")
            });

            var oktaId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;
            var idp = this.User.Claims.FirstOrDefault(x => x.Type == "idp").Value;

            //_userProfileModel.assignedApps = GetUserApps();
            //_userProfileModel.unassignedApps = GetAllApps();
            _userProfileModel = GetAppsUserData();

            oktaUser = (Okta.Sdk.User)client.Users.GetUserAsync(oktaId).Result;
            //common attributes
            if (oktaUser.Profile.Email != null) { _userProfileModel.email = oktaUser.Profile.Email; }
            if (oktaUser.Profile.FirstName != null) { _userProfileModel.firstName = oktaUser.Profile.FirstName; }
            if (oktaUser.Profile.LastName != null) { _userProfileModel.lastName = oktaUser.Profile.LastName;}

            //consumer attributes
            if (oktaUser.Profile["region"] != null) { _userProfileModel.region = oktaUser.Profile["region"].ToString(); }


            ////progressive consumer attributes
            //if (oktaUser.Profile["streetAddress"] != null) { _userProfileModel.streetAddress = oktaUser.Profile["streetAddress"].ToString(); }
            //if (oktaUser.Profile["city"] != null) { _userProfileModel.city = oktaUser.Profile["city"].ToString();}
            //if (oktaUser.Profile["state"] != null) { _userProfileModel.state = oktaUser.Profile["state"].ToString(); }
            //if (oktaUser.Profile["zipCode"] != null) { _userProfileModel.zipCode = oktaUser.Profile["zipCode"].ToString(); }


            //provider attributes
            if (oktaUser.Profile["licenseState"] != null) { _userProfileModel.licenseState = oktaUser.Profile["licenseState"].ToString();}
            if (oktaUser.Profile["physicianId"] != null) { _userProfileModel.physicianId = oktaUser.Profile["physicianId"].ToString(); }
            if (oktaUser.Profile["practiceName"] != null) { _userProfileModel.practiceName = oktaUser.Profile["practiceName"].ToString(); }

            //preferences
            if (oktaUser.Profile["Promotions"] != null) { _userProfileModel.Promotions = (bool)oktaUser.Profile["Promotions"]; }
            if (oktaUser.Profile["ProductUpdates"] != null) { _userProfileModel.ProductUpdates = (bool)oktaUser.Profile["ProductUpdates"];}
            if (oktaUser.Profile["Webinars"] != null) { _userProfileModel.Webinars = (bool)oktaUser.Profile["Webinars"];}


            //consent
            if (oktaUser.Profile["last_verification_date"] != null) { _userProfileModel.last_verification_date = oktaUser.Profile["last_verification_date"].ToString();}
            if (oktaUser.Profile["consent"] != null) { _userProfileModel.consent = oktaUser.Profile["consent"].ToString();}

            //misc
            if (oktaUser.Profile["level_of_assurance"] != null) { _userProfileModel.level_of_assurance = oktaUser.Profile["level_of_assurance"].ToString();}
            if (oktaUser.Profile["primaryRole"] != null) { _userProfileModel.primaryRole = oktaUser.Profile["primaryRole"].ToString(); }
            _userProfileModel.oktaId = oktaId;
            _userProfileModel.auth_idp = idp;

            TempData["IsRsp"] = false;
            return View(_userProfileModel);
            //return View(HttpContext.User.Claims);
        }

        [Authorize]
        public IActionResult Account()
        {
            //prior to allowing profile update
            //require additional factor, Email MFA

            //?? different profile for consumer and provider ??

            //display current profile
            Okta.Sdk.User oktaUser = null;


            var client = new OktaClient(new OktaClientConfiguration
            {
                OktaDomain = _config.GetValue<string>("OktaWeb:OktaDomain"),
                Token = _config.GetValue<string>("OktaWeb:ApiToken")
            });

            var oktaId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;
            var idp = this.User.Claims.FirstOrDefault(x => x.Type == "idp").Value;

            //_userProfileModel.assignedApps = GetUserApps();
            //_userProfileModel.unassignedApps = GetAllApps();
            _userProfileModel = GetAppsUserData();

            oktaUser = (Okta.Sdk.User)client.Users.GetUserAsync(oktaId).Result;
            //common attributes
            if (oktaUser.Profile.Email != null) { _userProfileModel.email = oktaUser.Profile.Email; }
            if (oktaUser.Profile.FirstName != null) { _userProfileModel.firstName = oktaUser.Profile.FirstName; }
            if (oktaUser.Profile.LastName != null) { _userProfileModel.lastName = oktaUser.Profile.LastName; }

            //consumer attributes
            if (oktaUser.Profile["region"] != null) { _userProfileModel.region = oktaUser.Profile["region"].ToString(); }


            ////progressive consumer attributes
            if (oktaUser.Profile["streetAddress"] != null) { _userProfileModel.streetAddress = oktaUser.Profile["streetAddress"].ToString(); }
            if (oktaUser.Profile["city"] != null) { _userProfileModel.city = oktaUser.Profile["city"].ToString();}
            if (oktaUser.Profile["state"] != null) { _userProfileModel.state = oktaUser.Profile["state"].ToString(); }
            if (oktaUser.Profile["zipCode"] != null) { _userProfileModel.zipCode = oktaUser.Profile["zipCode"].ToString(); }


            //provider attributes
            if (oktaUser.Profile["licenseState"] != null) { _userProfileModel.licenseState = oktaUser.Profile["licenseState"].ToString(); }
            if (oktaUser.Profile["physicianId"] != null) { _userProfileModel.physicianId = oktaUser.Profile["physicianId"].ToString(); }
            if (oktaUser.Profile["practiceName"] != null) { _userProfileModel.practiceName = oktaUser.Profile["practiceName"].ToString(); }

            //preferences
            if (oktaUser.Profile["Promotions"] != null) { _userProfileModel.Promotions = (bool)oktaUser.Profile["Promotions"]; }
            if (oktaUser.Profile["ProductUpdates"] != null) { _userProfileModel.ProductUpdates = (bool)oktaUser.Profile["ProductUpdates"]; }
            if (oktaUser.Profile["Webinars"] != null) { _userProfileModel.Webinars = (bool)oktaUser.Profile["Webinars"]; }


            //consent
            if (oktaUser.Profile["last_verification_date"] != null) { _userProfileModel.last_verification_date = oktaUser.Profile["last_verification_date"].ToString(); }
            if (oktaUser.Profile["consent"] != null) { _userProfileModel.consent = oktaUser.Profile["consent"].ToString(); }

            //misc
            //if (oktaUser.Profile["level_of_assurance"] != null) { _userProfileModel.level_of_assurance = oktaUser.Profile["level_of_assurance"].ToString(); }
            //if (oktaUser.Profile["primaryRole"] != null) { _userProfileModel.primaryRole = oktaUser.Profile["primaryRole"].ToString(); }


            //check user OIDC Consen
            string userId = oktaId;

            CollectionClient<Okta.Sdk.IResource> myCollection = client.GetCollection<Okta.Sdk.IResource>(new Okta.Sdk.HttpRequest
            {
                Uri = $"/api/v1/users/{userId}/grants",
                PathParameters = new Dictionary<string, object>()
                {
                    ["userId"] = userId,
                }
            });

            var myConsent = myCollection.ToListAsync().Result;
            foreach (var consent in myConsent)
            {
                var myData  = consent.GetData();
                string myScopeId = myData.FirstOrDefault(x => x.Key == "scopeId").Value.ToString();
                Dictionary<string,object> myLinks = (Dictionary<string, object>)myData.FirstOrDefault(x => x.Key == "_links").Value;
                Dictionary<string, object> myScope = (Dictionary<string, object>)myLinks.FirstOrDefault(x => x.Key == "scope").Value;
                string myTitle = myScope.FirstOrDefault(x => x.Key == "title").Value.ToString();
                ScopeConsentModel scopeModel = new ScopeConsentModel();
                scopeModel.scopeId = myScopeId;
                scopeModel.scopeTitle = myTitle;
                _userProfileModel.listScopedConsent.Add(scopeModel);
            }

            _userProfileModel.oktaId = oktaId;
            _userProfileModel.auth_idp = idp;

            TempData["IsRsp"] = false;
            return View(_userProfileModel);
            //return View(HttpContext.User.Claims);
        }

        [HttpPost]
        [Authorize]
        public IActionResult ProfileRoute([FromForm] UpdateProfileModel updateUser)
        {


            var destPage = _config.GetValue<string>("SendApi:UpdateProfileFlo");
            string consentToken = _config.GetValue<string>("SendApi:UpdateProfileToken");
            IRestResponse response = null;


            var client = new RestClient(destPage);
            var request = new RestRequest(Method.POST);
            // request.AddHeader("cache-control", "no-cache");
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("x-api-client-token", consentToken);
            request.AddJsonBody(updateUser);
            response = client.Execute(request);


            if (response.StatusDescription == "Forbidden" || response.StatusDescription == "Unauthorized")
            {

            }


            if (response.StatusDescription == "OK")
            {

            }
            else
            {

            }

            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        [Authorize]
        public IActionResult PrefenceRoute([FromForm] UpdatePreferenceModel updateUser)
        {


            var destPage = _config.GetValue<string>("SendApi:UpdatePreferenceFlo");
            string consentToken = _config.GetValue<string>("SendApi:UpdatePreferenceToken");
            IRestResponse response = null;


            var client = new RestClient(destPage);
            var request = new RestRequest(Method.POST);
            // request.AddHeader("cache-control", "no-cache");
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("x-api-client-token", consentToken);
            request.AddJsonBody(updateUser);
            response = client.Execute(request);


            if (response.StatusDescription == "Forbidden" || response.StatusDescription == "Unauthorized")
            {

            }


            if (response.StatusDescription == "OK")
            {

            }
            else
            {

            }
            return RedirectToAction("Index", "Home");
        }


        //[Authorize]
        //public IActionResult OidcConsent()
        //{
        //    if (HttpContext.User.Identity.IsAuthenticated)
        //    {
        //        _userProfileModel = GetAppsUserData();
        //    }

        //    TempData["IsRsp"] = false;
        //    return View("Index",_userProfileModel);
        //}


        [HttpPost]
        [Authorize]
        public IActionResult OidcConsentRoute([FromForm] string oktaId, string sensitiveData, string scopeId)
        {

            var client = new OktaClient(new OktaClientConfiguration
            {
                OktaDomain = _config.GetValue<string>("OktaWeb:OktaDomain"),
                Token = _config.GetValue<string>("OktaWeb:ApiToken")
            });

            string userId = oktaId;

            var myResource = client.DeleteAsync(new Okta.Sdk.HttpRequest
            {
                Uri = $"/api/v1/users/{userId}/grants",
                PathParameters = new Dictionary<string, object>()
                {
                    ["userId"] = oktaId,
                }
            });

            return RedirectToAction("Index", "Home");
        }




        [Authorize]
        public IActionResult Consent()
        {
            //if (HttpContext.User.Identity.IsAuthenticated)
            //{
            //    _userProfileModel = GetAppsUserData();
            //}

            //TempData["IsRsp"] = false;
            //return View(_userProfileModel);
            return RedirectToAction("Index", "Home");
        }


        [HttpPost]
        [Authorize]
        public IActionResult ConsentRoute(string getConsent)
        {
            var destPage = _config.GetValue<string>("SendApi:ConsentFlo");
            string consentToken = _config.GetValue<string>("SendApi:ConsentToken");
            IRestResponse response = null;

            WorkflowModels userConsentModel = new WorkflowModels();
            userConsentModel.oktaId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;
            userConsentModel.consent = getConsent;


            var client = new RestClient(destPage);
            var request = new RestRequest(Method.POST);
            // request.AddHeader("cache-control", "no-cache");
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("x-api-client-token", consentToken);
            request.AddJsonBody(userConsentModel);
            response = client.Execute(request);


            if (response.StatusDescription == "Forbidden" || response.StatusDescription == "Unauthorized")
            {

            }


            if (response.StatusDescription == "OK")
            {

            }
            else
            {

            }

            return RedirectToAction("Index", "Home");
        }

        [Authorize]
        public IActionResult AdPush()
        {

            //List<AppLink> userAppList = new List<AppLink>();

            //var client = new OktaClient(new OktaClientConfiguration
            //{
            //    OktaDomain = _config.GetValue<string>("OktaWeb:OktaDomain"),
            //    Token = _config.GetValue<string>("OktaWeb:ApiToken")
            //});

            //var oktaId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;



            //client.Groups.AddUserToGroupAsync("00g4e8cmt3ZqIRtGu1d6", oktaId); //ad push
            //                                                                   //client.Groups.AddUserToGroupAsync("00g46izursODbUldm1d6", oktaId).Wait(); //test group

            var destPage = _config.GetValue<string>("SendApi:ADPushFlo");
            string consentToken = _config.GetValue<string>("SendApi:ADPushToken");
            IRestResponse response = null;

            

            WorkflowModels addAdUser = new WorkflowModels();
            addAdUser.oktaId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;

            var client = new RestClient(destPage);
            var request = new RestRequest(Method.POST);
            // request.AddHeader("cache-control", "no-cache");
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("x-api-client-token", consentToken);
            request.AddJsonBody(addAdUser);
            response = client.Execute(request);


            if (response.StatusDescription == "Forbidden" || response.StatusDescription == "Unauthorized")
            {

            }


            if (response.StatusDescription == "OK")
            {

            }
            else
            {

            }
            return RedirectToAction("Index", "Home");


            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userProfileModel = GetAppsUserData();
            }

            TempData["IsRsp"] = true;
            TempData["title"] = "Application Request Submitted";
            TempData["message1"] = "User Provisioned to Active Directory";
            TempData["message2"] = "Note: It may take a moment...";
            return View("Index", _userProfileModel);
        }

        [Authorize]
        public IActionResult SendApi()
        {
            //from asp.net middleware
            var accessToken = HttpContext.GetTokenAsync("access_token").Result;
            //var refreshToken = HttpContext.GetTokenAsync("refresh_token").Result;
            //var expiresAt = DateTimeOffset.Parse( HttpContext.GetTokenAsync("expires_at").Result);

            //from user.Identity Claims
            //string myAccessToken = HttpContext.User.Claims.FirstOrDefault(x => x.Type == "accessToken").Value;

            string rspSendApi = SendTokenToWebApi(accessToken, _config.GetValue<string>("SendApi:BackendApi"));

            //var modRsp = JObject.Parse(rspSendApi);
            //ApiResponseModel anotherMod = JsonConvert.DeserializeObject<ApiResponseModel>(rspSendApi);

            //ViewData["apiRsp"] = anotherMod;
            //if (HttpContext.User.Identity.IsAuthenticated)
            //{
            //    //_userProfileModel.assignedApps = GetUserApps();
            //    //_userProfileModel.unassignedApps = GetAllApps();
            //    _userProfileModel = GetAppsUserData();
            //}
            //TempData["IsRsp"] = false;
            //return View(_userProfileModel);
            return RedirectToAction("Token", new { resourceServerData = rspSendApi });
        }


        public string SendTokenToWebApi(string access_token, string destPage)
        {
            string rsp = "Api call failed";

            IRestResponse response = null;

            var client = new RestClient(destPage);
            var request = new RestRequest(Method.GET);
            // request.AddHeader("cache-control", "no-cache");
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("Authorization", "Bearer " + access_token);
            response = client.Execute(request);

            if (response.StatusDescription == "Forbidden" || response.StatusDescription == "Unauthorized")
            {
                return rsp;
            }


            if (response.StatusDescription == "OK")
            {
                return response.Content;       
            }
            else
            {
                return rsp;
            }
        }


    }
}
