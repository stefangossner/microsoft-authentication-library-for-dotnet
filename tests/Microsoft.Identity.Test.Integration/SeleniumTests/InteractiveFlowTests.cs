using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.PlatformsCommon.Factories;
using Microsoft.Identity.Test.Common;
using Microsoft.Identity.Test.Integration.Infrastructure;
using Microsoft.Identity.Test.LabInfrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenQA.Selenium;
using System;
using System.Diagnostics;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Identity.Client.AppConfig;
using Microsoft.Identity.Test.Unit;
using System.Globalization;
using Microsoft.Identity.Test.UIAutomation.Infrastructure;

namespace Microsoft.Identity.Test.Integration.SeleniumTests
{
    [TestClass]
    public class InteractiveFlowTests
    {
        private readonly TimeSpan _seleniumTimeout = TimeSpan.FromMinutes(2);
        private TokenCache cache;

        #region MSTest Hooks
        /// <summary>
        /// Initialized by MSTest (do not make private or readonly)
        /// </summary>
        public TestContext TestContext { get; set; }

        [ClassInitialize]
        public static void ClassInitialize(TestContext context)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        }

        [TestInitialize]
        public void TestInitialize()
        {
            TestCommon.ResetStateAndInitMsal();
        }

        #endregion

        [TestMethod]
        public async Task InteractiveAuth_DefaultUserAsync()
        {
            // Arrange
            LabResponse labResponse = LabUserHelper.GetDefaultUser();
            await RunTestForUserInteractiveAsync(labResponse).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task Interactive_AdfsV3_NotFederatedAsync()
        {
            // Arrange
            UserQuery query = new UserQuery
            {
                FederationProvider = FederationProvider.AdfsV4,
                IsMamUser = false,
                IsMfaUser = false,
                IsFederatedUser = false
            };


            LabResponse labResponse = LabUserHelper.GetLabUserData(query);
            await RunTestForUserInteractiveAsync(labResponse).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task Interactive_AdfsV3_FederatedAsync()
        {
            // Arrange
            UserQuery query = new UserQuery
            {
                FederationProvider = FederationProvider.AdfsV4,
                IsMamUser = false,
                IsMfaUser = false,
                IsFederatedUser = true
            };

            LabResponse labResponse = LabUserHelper.GetLabUserData(query);
            await RunTestForUserInteractiveAsync(labResponse).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task Interactive_AdfsV2_FederatedAsync()
        {
            // Arrange
            UserQuery query = new UserQuery
            {
                FederationProvider = FederationProvider.AdfsV2,
                IsMamUser = false,
                IsMfaUser = false,
                IsFederatedUser = true
            };


            LabResponse labResponse = LabUserHelper.GetLabUserData(query);
            await RunTestForUserInteractiveAsync(labResponse).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task Interactive_AdfsV4_NotFederatedAsync()
        {
            // Arrange
            UserQuery query = new UserQuery
            {
                FederationProvider = FederationProvider.AdfsV4,
                IsMamUser = false,
                IsMfaUser = false,
                IsFederatedUser = false
            };

            LabResponse labResponse = LabUserHelper.GetLabUserData(query);
            await RunTestForUserInteractiveAsync(labResponse).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task Interactive_AdfsV4_FederatedAsync()
        {
            // Arrange
            UserQuery query = new UserQuery
            {
                FederationProvider = FederationProvider.AdfsV4,
                IsMamUser = false,
                IsMfaUser = false,
                IsFederatedUser = true
            };

            LabResponse labResponse = LabUserHelper.GetLabUserData(query);
            await RunTestForUserInteractiveAsync(labResponse).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task Interactive_AdfsV2019_NotFederatedAsync()
        {
            // Arrange
            UserQuery query = new UserQuery
            {
                FederationProvider = FederationProvider.ADFSv2019,
                IsMamUser = false,
                IsMfaUser = false,
                IsFederatedUser = false
            };

            LabResponse labResponse = LabUserHelper.GetLabUserData(query);
            await RunTestForUserInteractiveAsync(labResponse).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task Interactive_AdfsV2019_FederatedAsync()
        {
            // Arrange
            UserQuery query = new UserQuery
            {
                FederationProvider = FederationProvider.ADFSv2019,
                IsMamUser = false,
                IsMfaUser = false,
                IsFederatedUser = true
            };

            LabResponse labResponse = LabUserHelper.GetLabUserData(query);
            await RunTestForUserInteractiveAsync(labResponse).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task Interactive_AdfsV2019_DirectAsync()
        {
            // Arrange
            UserQuery query = new UserQuery
            {
                FederationProvider = FederationProvider.ADFSv2019,
                IsMamUser = false,
                IsMfaUser = false,
                IsFederatedUser = true
            };

            LabResponse labResponse = LabUserHelper.GetLabUserData(query);
            await RunTestForUserInteractiveAsync(labResponse, true).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task MultiUserCacheCompatabilityTestAsync()
        {
            // Arrange
            cache = new TokenCache();

            LabResponse labResponseDefault = LabUserHelper.GetDefaultUser();
            var defaultAccountResult = await RunTestForUserInteractiveAsync(labResponseDefault).ConfigureAwait(false);

            UserQuery FederatedUserquery = new UserQuery
            {
                FederationProvider = FederationProvider.ADFSv2019,
                IsMamUser = false,
                IsMfaUser = false,
                IsFederatedUser = true
            };

            LabResponse labResponseFederated = LabUserHelper.GetLabUserData(FederatedUserquery);
            var federatedAccountResult = await RunTestForUserInteractiveAsync(labResponseFederated, true).ConfigureAwait(false);

            UserQuery MSAUserquery = new UserQuery
            {
                UserSearch = LabApiConstants.MSAOutlookAccount,
                IsExternalUser = true,
                AppName = "Lab4V2App"
            };

            LabResponse labResponseMsa = LabUserHelper.GetLabUserData(MSAUserquery);
            labResponseMsa.AppId = LabApiConstants.MSAOutlookAccountClientID;
            var msaAccountResult = await RunTestForUserInteractiveAsync(labResponseMsa).ConfigureAwait(false);

            PublicClientApplication pca = PublicClientApplicationBuilder.Create(labResponseDefault.AppId).BuildConcrete();
            pca.UserTokenCacheInternal = cache;

            AuthenticationResult authResult = await pca.AcquireTokenSilentAsync(new[] { CoreUiTestConstants.DefaultScope }, defaultAccountResult.Account).ConfigureAwait(false);
            Assert.IsNotNull(authResult);
            Assert.IsNotNull(authResult.AccessToken);
            Assert.IsNotNull(authResult.IdToken);

            pca = PublicClientApplicationBuilder.Create(labResponseFederated.AppId).BuildConcrete();
            pca.UserTokenCacheInternal = cache;

            authResult = await pca.AcquireTokenSilentAsync(new[] { CoreUiTestConstants.DefaultScope },
                   federatedAccountResult.Account).ConfigureAwait(false);
            Assert.IsNotNull(authResult);
            Assert.IsNotNull(authResult.AccessToken);
            Assert.IsNull(authResult.IdToken);

            pca = PublicClientApplicationBuilder.Create(LabApiConstants.MSAOutlookAccountClientID).BuildConcrete();
            pca.UserTokenCacheInternal = cache;

            authResult = await pca.AcquireTokenSilentAsync(new[] { CoreUiTestConstants.DefaultScope }, msaAccountResult.Account).ConfigureAwait(false);
            Assert.IsNotNull(authResult);
            Assert.IsNotNull(authResult.AccessToken);
            Assert.IsNull(authResult.IdToken);

            cache = null;
        }

        private async Task<AuthenticationResult> RunTestForUserInteractiveAsync(LabResponse labResponse, bool directToAdfs = false)
        {
            Action<IWebDriver> seleniumLogic = (driver) =>
            {
                Trace.WriteLine("Starting Selenium automation");
                driver.PerformLogin(labResponse.User, directToAdfs);
            };

            SeleniumWebUIFactory webUIFactory = new SeleniumWebUIFactory(seleniumLogic, _seleniumTimeout);

            PublicClientApplication pca;
            if(directToAdfs)
            {
                pca = PublicClientApplicationBuilder.Create(Adfs2019LabConstants.PublicClientId)
                                                    .WithRedirectUri(Adfs2019LabConstants.ClientRedirectUri)
                                                    .WithAdfsAuthority(Adfs2019LabConstants.Authority)
                                                    .BuildConcrete();
            }
            else
            {
                pca = PublicClientApplicationBuilder.Create(labResponse.AppId)
                                                    .WithRedirectUri(SeleniumWebUIFactory.FindFreeLocalhostRedirectUri())
                                                    .BuildConcrete();
            }
            if (cache != null)
            {
                cache.SetServiceBundle(pca.ServiceBundle);
                pca.UserTokenCacheInternal = cache;
            }

            pca.ServiceBundle.PlatformProxy.SetWebUiFactory(webUIFactory);

            // Act
            AuthenticationResult result = await pca.AcquireTokenAsync(new[] { CoreUiTestConstants.DefaultScope }).ConfigureAwait(false);

            // Assert
            Assert.IsFalse(string.IsNullOrWhiteSpace(result.AccessToken));

            return result;
        }
    }

}
