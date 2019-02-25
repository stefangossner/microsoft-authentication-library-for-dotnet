//----------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Identity.Client.Platforms.Android
{
    internal class AndroidBrokerConstants
    {
        public const int BrokerRequestId = 1177;

        public const string BrokerRequest = "com.microsoft.aadbroker.adal.broker.request";

        public const string BrokerRequestResume = "com.microsoft.aadbroker.adal.broker.request.resume";

        /**
         * Account type string.
         */
        public const string BrokerAccountType = "com.microsoft.workaccount";

        public const string WorkAccount = "com.microsoft.workaccount.user.info";

        public const string AccountInitialName = "aad";

        public const string BackgroundRequestMessage = "background.request";

        public const string AccountDefaultName = "Default";

        /**
         * Authtoken type string.
         */
        public const string AuthtokenType = "adal.authtoken.type";

        public const string BrokerFinalUrl = "adal.final.url";

        public const string AccountInitialRequest = "account.initial.request";

        public const string AccountClientIdKey = "account.clientid.key";

        public const string AccountClientSecretKey = "account.client.secret.key";

        public const string AccountCorrelationId = "account.correlationid";

        public const string AccountPrompt = "account.prompt";

        public const string AccountExtraQueryParam = "account.extra.query.param";

        public const string AccountLoginHint = "account.login.hint";

        public const string AccountResource = "account.resource";

        public const string AccountRedirect = "account.redirect";

        public const string AccountAuthority = "account.authority";

        public const string AccountRefreshToken = "account.refresh.token";

        public const string AccountAccessToken = "account.access.token";

        public const string AccountExpireDate = "account.expiredate";

        public const string AccountResult = "account.result";

        public const string AccountRemoveTokens = "account.remove.tokens";

        public const string AccountRemoveTokensValue = "account.remove.tokens.value";

        public const string MultiResourceToken = "account.multi.resource.token";

        public const string AccountName = "account.name";

        public const string AccountIdToken = "account.idtoken";

        public const string AccountUserInfoUserId = "account.userinfo.userid";

        public const string AccountUserInfoGivenName = "account.userinfo.given.name";

        public const string AccountUserInfoFamilyName = "account.userinfo.family.name";

        public const string AccountUserInfoIdentityProvider = "account.userinfo.identity.provider";

        public const string AccountUserInfoUserIdDisplayable = "account.userinfo.userid.displayable";

        public const string AccountUserInfoTenantId = "account.userinfo.tenantid";

        public const string AdalVersionKey = "adal.version.key";

        public const string AccountUidCaches = "account.uid.caches";

        public const string UserdataPrefix = "userdata.prefix";

        public const string UserdataUidKey = "calling.uid.key";

        public const string UserdataCallerCachekeys = "userdata.caller.cachekeys";

        public const string CallerCachekeyPrefix = "|";

        public const string ClientTlsNotSupported = " PKeyAuth/1.0";

        public const string ChallangeRequestHeader = "WWW-Authenticate";

        public const string ChallangeResponseHeader = "Authorization";

        public const string ChallangeResponseType = "PKeyAuth";

        public const string ChallangeResponseToken = "AuthToken";

        public const string ChallangeResponseContext = "Context";

        public const string ChallangeResponseVersion = "Version";

        public const string ResponseErrorCode = "com.microsoft.aad.adal:BrowserErrorCode";

        public const string ResponseErrorMessage = "com.microsoft.aad.adal:BrowserErrorMessage";

        public const string SHA = "SHA";

        /**
         * Certificate authorities are passed with delimiter.
         */
        public const string ChallangeRequestCertAuthDelimeter = ";";

        /**
         * Apk packagename that will install AD-Authenticator. It is used to
         * query if this app installed or not from package manager.
         */
        public const string PackageName = "com.microsoft.windowsintune.companyportal";

        /**
         * Signature info for Intune Company portal app that installs authenticator
         * component.
         */
        public const string Signature = "1L4Z9FJCgn5c0VLhyAxC5O9LdlE=";

        /**
         * Signature info for Azure authenticator app that installs authenticator
         * component.
         */
        public const string AzureAuthenticatorAppSignature = "ho040S3ffZkmxqtQrSwpTVOn9r0=";

        public const string AzureAuthenticatorAppPackageName = "com.azure.authenticator";

        public const string ClientTlsRedirect = "urn:http-auth:PKeyAuth";

        public const string ChallangeTlsIncapable = "x-ms-PKeyAuth";

        public const string ChallangeTlsIncapableVersion = "1.0";

        public const string RedirectPrefix = "msauthv2";

        //public const Object REDIRECT_DELIMETER_ENCODED = "%2C";

        public const string BrowserExtPrefix = "browser://";

        public const string BrowserExtInstallPrefix = "msauthv2://";

        public const string CallerInfoPackage = "caller.info.package";

        public const string CallerInfoUID = "caller.info.uid";

        // Claims step-up. Skip cache look up
        public const string SkipCache = "skip.cache";
        public const string Claims = "account.claims";

        public const string AccountChooserActivity = ".ui.AccountChooserActivity";

        public const string CanInvokeBroker = "Can invoke broker? ";

        // Broker related log messages
        public const string BrokerProxyGettingTheAndroidContext = "BrokerProxy: Getting the Android context";
        public const string BrokerProxyGettingTheBrokerWorkAndSchoolAccounts = "BrokerProxy: Getting the broker work and school accounts ";
        public const string BrokerProxyTheBrokerFoundSomeAccounts = "BrokerProxy: The broker found some accounts";
        public const string BrokerProxyFoundAccountBasedonBrokerAccountName = "BrokerProxy: Found account based on the broker account name? ";
        public const string BrokerProxyNoBrokerAccountGettingBrokerUsers = "BrokerProxy: No broker account - getting broker users";
        public const string BrokerProxyFoundSomeBrokerUsers = "Broker Proxy: Found some broker users";
        public const string BrokerProxyFoundAMatchingUser = "BrokerProxy: Found a matching user? ";
        public const string BrokerProxyFoundAMatchingAccountBasedOnTheUser = "BrokerProxy: Found a matching account based on the user? ";
        public const string BrokerProxyInvokingTheBrokerToGetAToken = "BrokerProxy: Invoking the broker to get a token";
        public const string BrokerProxyReceivedResultFromAuthenticator = "BrokerProxy: Received result from Authenticator? ";
        public const string BrokerProxyReturningResultFromAuthenticator = "BrokerProxy: Returning result from Authenticator ? ";
        public const string BrokerProxyTargetAccountIsNotFound = "Target account is not found";
        public const string BrokerProxyFindingAccount = "BrokerProxy: Finding Account... ";
        public const string BrokerProxyLookingForAMatchWithBrokerAccount = "Broker Proxy: Looking for a match with broker account. Found? ";
        public const string BrokerProxyInitialRequestNotReturningAToken = "BrokerProxy: Initial request - not returning a token. ";
        public const string CallingAppPackageDoesNotExistInPackageManager = "BrokerProxy: Calling App's package does not exist in PackageManager. ";
        public const string DigestShaAlgorithmDoesNotExist = "Digest SHA algorithm does not exist. ";
        public const string BrokerProxyCheckAccountIsGettingTheAuthenticatorTypes = "BrokerProxy: CheckAccount. Getting authenticator types: ";
        public const string BrokerProxyGettingTheAccountList = "BrokerProxy: Getting the account list ";
        public const string BrokerProxyCheckingTheAccountFailedBecauseTheBrokerPackageWasNotFound = "BrokerProxy: Checking the account failed because the broker package was not found. ";
        public const string BrokerProxyPackageName = "BrokerProxy: Package name is: ";
        public const string BrokerProxyBrokerSupportsAddingAccounts = "BrokerProxy: Broker supports adding accounts. ";
        public const string BrokerProxyBrokerDoesNotSupportAddingAccountsButSomeAccountsAreConfiguredVerifyingIfAnAccountCanBeUsed =
            "BrokerProxy: Broker does not support adding accounts but some accounts are configured. Verifying if an account can be used...";
        public const string BrokerProxyCouldNotVerifyThatAnAccountCanBeUsed = "BrokerProxy: Could not verify that an account can be used. ";
        public const string BrokerProxyStartingAccountVerification = "BrokerProxy: starting account verification. ";
        public const string BrokerProxyFoundAnAccountThatMatchesTheUsername = "BrokerProxy: Found an account that matches the username? ";
        public const string BrokerProxyCouldNotVerifyAnAccountBecauseOfAnException = "BrokerProxy: Could not verify an account because of an exception. ";
        public const string BrokerProxyCouldNotVerifyTheAccount = "BrokerProxy: Could not verify the account. ";
        public const string BrokerProxyAccountVerificationPassed = "BrokerProxy: Account verification passed. ";
        public const string BrokerProxyFoundTheAuthenticatorOnTheDevice = "BrokerProxy: Found the Authenticator on the device";
        public const string BrokerProxyNoAuthenticatorFoundOnTheDevice = "BrokerProxy: No Authenticator found on the device.";

        public const string AndroidBrokerPayloadContainsInstallUrl = "Android Broker - broker payload contains install url";
        public const string AndroidBrokerStartingActionViewActivityTo = "Android Broker - Starting ActionView activity to: ";
        public const string SwitchedToBrokerForContext = "Switched to broker for context: ";
        public const string LoginHint = " login hint: ";
        public const string UserIsSpecifiedForBackgroundTokenRequest = "User is specified for background token request ";
        public const string UserIsNotSpecifiedForBackgroundTokenRequest = "User is not specified for background token request ";
        public const string TokenIsReturnedFromBackgroundCall = "Token is returned from background call ";
        public const string TokenIsNotReturnedFromBackgroundCallLaunchActivityForAuthenticator = "Token is not returned from background call. Will launch activity for Authenticator." +
            "Starting Authentication Activity... ";
        public const string CannotInvokeBrokerInInteractiveModeBecauseThisIsASilentFlow = "Can't invoke the broker in interactive mode because this is a silent flow ";
        public const string CallingActivityPid = "Calling activity pid:";
        public const string tid = " tid: ";
        public const string uid = " uid: ";


        public static string BrokerProxyAccountFoundMessage(bool found)
        {
            return BrokerProxyLookingForAMatchWithBrokerAccount + found;
        }
    }
}
