using Okta.Sdk;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace okta_aspnetcore_mvc_example.Models
{
    public class WorkflowModels
    {
        public string oktaId { get; set; }
        public string consent { get; set; }

    }


    public class RegisterUserModel
    {
        public string email { get; set; }
        public string password { get; set; }
        public string firstName { get; set; }
        public string lastName { get; set; }

        public string region { get; set; }

        //consumer attributes
        public string streetAddress { get; set; }
        public string city { get; set; }
        public string state { get; set; }
        public string zipCode { get; set; }

        public string insuranceCarrier { get; set; }
        public string insuranceId { get; set; }

    }


    public class UpdateProfileModel
    {
        public string oktaId { get; set; }
        //common attributes
        public string email { get; set; }
        public string firstName { get; set; }
        public string lastName { get; set; }

        //consumer attributes
        public string streetAddress { get; set; }
        public string city { get; set; }
        public string state { get; set; }
        public string zipCode { get; set; }
        public string region { get; set; }
        public string insuranceCarrier { get; set; }
        public string insuranceId { get; set; }

        //provider attributes
        //public string licenseState { get; set; }
        //public string physicianId { get; set; }
        //public string practiceName { get; set; }

    }


    public class UpdatePreferenceModel
    {
        public string oktaId { get; set; }
        //preferences
        public bool Promotions { get; set; }
        public bool ProductUpdates { get; set; }
        public bool Webinars { get; set; }
    }


    public class UserProfileModel
    {
        //common attributes
        public string email { get; set; }
        public string firstName { get; set; }
        public string lastName { get; set; }

        //consumer attributes
        //public string region { get; set; }

        //consumer attributes
        public string streetAddress { get; set; }
        public string city { get; set; }
        public string state { get; set; }
        public string zipCode { get; set; }
        public string region { get; set; }
        public string insuranceCarrier { get; set; }
        public string insuranceId { get; set; }

        //provider attributes
        public string licenseState { get; set; }
        public string physicianId { get; set; }
        public string practiceName { get; set; }

        //preferences
        public bool Promotions { get; set; }
        public bool ProductUpdates { get; set; }
        public bool Webinars { get; set; }

        //consent
        public string consent { get; set; }
        public string level_of_assurance { get; set; }
        public string last_verification_date { get; set; }

        //app related
        public string auth_idp { get; set; }
        public string oktaId { get; set; }
        public string primaryRole { get; set; }
        public List<AppLink> listAssignedApps { get; set; }
        public List<string> unassignedApps { get; set; }
        public List<PresentUserModel> listCustodians { get; set; }

        public List<PresentUserModel> listDependants { get; set; }
        public List<PresentUserModel> listPermissions { get; set; }

        public List<PresentUserModel> listDelegates { get; set; }

        public List<ScopeConsentModel> listScopedConsent { get; set; }
    }


    public class ScopeConsentModel
    {
        public string scopeId { get; set; }
        public string scopeTitle { get; set; }
    }


    //public class PermissionModel
    //{
    //    public string userName { get; set; }
    //    public string oktaId { get; set; }
    //    public string email { get; set; }
    //}

    public class PresentUserModel
    {
        public string userName { get; set; }
        public string oktaId { get; set; }
        public string email { get; set; }
    }

    public class RequestAppModel
    {
        public string appName { get; set; }
        public string oktaId { get; set; }
        public string email { get; set; }
    }

    public class LinkedUserModel
    {
        public string childFirstName { get; set; }
        public string childLastName { get; set; }
        public string childEmail { get; set; }
        public string childOktaId { get; set; }
        public string parentOktaId { get; set; }
        public string parentEmail { get; set; }
        public string searchCriteria { get; set; }
    }



}
