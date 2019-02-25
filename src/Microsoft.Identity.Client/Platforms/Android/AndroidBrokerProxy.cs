//------------------------------------------------------------------------------
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

using Android.Accounts;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Android.Util;
using Java.Security;
using Java.Util.Concurrent;
using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.Exceptions;
using Microsoft.Identity.Client.Internal.Broker;
using Microsoft.Identity.Client.Internal.Requests;
using Microsoft.Identity.Client.OAuth2;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using OperationCanceledException = Android.Accounts.OperationCanceledException;
using Permission = Android.Content.PM.Permission;
using Signature = Android.Content.PM.Signature;

namespace Microsoft.Identity.Client.Platforms.Android
{
    internal class AndroidBrokerProxy
    {
        private const string RedirectUriScheme = AndroidBrokerConstants.RedirectPrefix;
        private const string BrokerTag = AndroidBrokerConstants.Signature;
        public const string WorkAccount = AndroidBrokerConstants.WorkAccount;

        private readonly Context _androidContext;
        private readonly AccountManager _androidAccountManager;
        private IServiceBundle _serviceBundle;

        public AndroidBrokerProxy(Context androidContext, IServiceBundle serviceBundle)
        {
            _androidContext = androidContext ?? throw new ArgumentNullException(nameof(androidContext));
            _serviceBundle = serviceBundle;

            _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.BrokerProxyGettingTheAndroidContext);
            _androidAccountManager = AccountManager.Get(_androidContext);
        }

        public bool CanSwitchToBroker()
        {
            string packageName = _androidContext.PackageName;

            // ADAL switches to broker for the following conditions:
            // 1- app is not skipping the broker
            // 2- permissions are set in the manifest,
            // 3- if package is not broker itself for both company portal and azure
            // authenticator
            // 4- signature of the broker is valid
            // 5- account exists
            return VerifyManifestPermissions()
                   && VerifyAuthenticator(_androidAccountManager)
                   && CheckAccount(_androidAccountManager, "", "")
                   && !packageName.Equals(AndroidBrokerConstants.PackageName, StringComparison.OrdinalIgnoreCase)
                   && !packageName
                       .Equals(AndroidBrokerConstants.AzureAuthenticatorAppPackageName, StringComparison.OrdinalIgnoreCase);
        }

        public bool VerifyUser(string username, string uniqueid)
        {
            return CheckAccount(_androidAccountManager, username, uniqueid);
        }

        public MsalTokenResponse GetAuthTokenInBackground(AndroidBrokerAuthenticationRequest brokerAuthenticationRequest, Activity callerActivity)
        {
            MsalTokenResponse msalTokenResponse = null;
            VerifyNotOnMainThread();

            // if there is no user added to the account, returns empty
            global::Android.Accounts.Account targetAccount = null;

            _serviceBundle.DefaultLogger.Info(AndroidBrokerConstants.BrokerProxyGettingTheBrokerWorkAndSchoolAccounts);

            global::Android.Accounts.Account[] accountList = _androidAccountManager
                .GetAccountsByType(AndroidBrokerConstants.BrokerAccountType);

            if (accountList != null && accountList.Length > 0)
            {
                _serviceBundle.DefaultLogger.Info(AndroidBrokerConstants.BrokerProxyTheBrokerFoundSomeAccounts);
            }


            if (!string.IsNullOrEmpty(brokerAuthenticationRequest.BrokerAccountName))
            {
                targetAccount = FindAccount(brokerAuthenticationRequest.BrokerAccountName, accountList);
                _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.BrokerProxyFoundAccountBasedonBrokerAccountName + (targetAccount != null));
            }
            else
            {
                try
                {
                    _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.BrokerProxyNoBrokerAccountGettingBrokerUsers);
                    IAccount[] accounts = GetBrokerAccounts();

                    if (accounts != null && accounts.Length > 0)
                    {
                        _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.BrokerProxyFoundSomeBrokerUsers);
                    }

                    IAccount matchingAccount = FindAccountInfo(brokerAuthenticationRequest.UserId, accounts);
                    _serviceBundle.DefaultLogger.Info(AndroidBrokerConstants.BrokerProxyFoundAMatchingUser + (matchingAccount != null));

                    if (matchingAccount != null)
                    {
                        // TODO: check what should be used here.
                        targetAccount = FindAccount(matchingAccount.Username, accountList);
                        _serviceBundle.DefaultLogger.Info(AndroidBrokerConstants.BrokerProxyFoundAMatchingAccountBasedOnTheUser + (targetAccount != null));
                    }
                }
                catch (Exception e)
                {
                    _serviceBundle.DefaultLogger.ErrorPii(e);
                }
            }

            if (targetAccount != null)
            {
                Bundle brokerOptions = GetBrokerOptions(brokerAuthenticationRequest);

                // blocking call to get token from cache or refresh request in
                // background at Authenticator
                IAccountManagerFuture result = null;
                try
                {
                    // It does not expect activity to be launched.
                    // AuthenticatorService is handling the request at
                    // AccountManager.
                    _serviceBundle.DefaultLogger.Info(AndroidBrokerConstants.BrokerProxyInvokingTheBrokerToGetAToken);

                    result = _androidAccountManager.GetAuthToken(
                        targetAccount,
                        AndroidBrokerConstants.AuthtokenType,
                        brokerOptions,
                        false,
                        null /* set to null to avoid callback */,
                        new Handler(callerActivity.MainLooper));

                    // Making blocking request here
                    _serviceBundle.DefaultLogger.InfoPii(AndroidBrokerConstants.BrokerProxyReceivedResultFromAuthenticator + (result != null), AndroidBrokerConstants.BrokerProxyReceivedResultFromAuthenticator);

                    Bundle bundleResult = (Bundle)result.GetResult(10000, TimeUnit.Milliseconds);
                    // Authenticator should throw OperationCanceledException if
                    // token is not available
                    msalTokenResponse = GetResultFromBrokerResponse(bundleResult);
                }
                catch (OperationCanceledException e)
                {
                    _serviceBundle.DefaultLogger.ErrorPii(e);
                }
                catch (AuthenticatorException e)
                {
                    _serviceBundle.DefaultLogger.ErrorPii(e);
                }
                catch (Java.Lang.Exception javaException)
                {
                    _serviceBundle.DefaultLogger.ErrorPii(javaException);
                }
                catch (Exception e)
                {
                    // Authenticator gets problem from webrequest or file read/write
                    /*                    Logger.e(TAG, "Authenticator cancels the request", "",
                                                ADALError.BROKER_AUTHENTICATOR_IO_EXCEPTION);*/

                    _serviceBundle.DefaultLogger.ErrorPii(e);
                }

                _serviceBundle.DefaultLogger.InfoPii(AndroidBrokerConstants.BrokerProxyReturningResultFromAuthenticator + (msalTokenResponse != null), AndroidBrokerConstants.BrokerProxyReturningResultFromAuthenticator);

                return msalTokenResponse;
            }
            else
            {
                _serviceBundle.DefaultLogger.Warning(AndroidBrokerConstants.BrokerProxyTargetAccountIsNotFound);
            }

            return null;
        }

        public Intent GetIntentForBrokerActivity(AndroidBrokerAuthenticationRequest brokerAuthenticationRequest, Activity callerActivity)
        {
            Intent intent = null;
            IAccountManagerFuture result = null;
            try
            {
                // Callback is not passed since it is making a blocking call to get
                // intent. Activity needs to be launched from calling app
                // to get the calling app's metadata if needed at BrokerActivity.
                Bundle addAccountOptions = GetBrokerOptions(brokerAuthenticationRequest);
                result = _androidAccountManager.AddAccount(
                    AndroidBrokerConstants.BrokerAccountType,
                    AndroidBrokerConstants.AuthtokenType,
                    null,
                    addAccountOptions,
                    null,
                    null,
                    new Handler(
                        callerActivity.MainLooper));

                // Making blocking request here
                Bundle bundleResult = (Bundle)result.Result;
                // Authenticator should throw OperationCanceledException if
                // token is not available
                intent = (Intent)bundleResult.GetParcelable(AccountManager.KeyIntent);

                // Add flag to this intent to signal that request is for broker
                if (intent != null)
                {
                    intent.PutExtra(AndroidBrokerConstants.BrokerRequest, AndroidBrokerConstants.BrokerRequest);
                }
            }
            catch (MsalException)
            {
                throw;
            }
            catch (Exception e)
            {
                _serviceBundle.DefaultLogger.ErrorPii(e);
            }

            return intent;
        }

        // App needs to give permission to AccountManager to use broker.
        private bool VerifyManifestPermissions()
        {
            return VerifyManifestPermission("android.permission.GET_ACCOUNTS") &&
                   VerifyManifestPermission("android.permission.MANAGE_ACCOUNTS") &&
                   VerifyManifestPermission("android.permission.USE_CREDENTIALS");
        }

        private bool VerifyManifestPermission(string permission)
        {
            if (Permission.Granted !=
                Application.Context.PackageManager.CheckPermission(permission, Application.Context.PackageName))
            {
                _serviceBundle.DefaultLogger.Warning(string.Format(CultureInfo.InvariantCulture,
                    MsalErrorMessageAndroidEx.MissingPackagePermissionTemplate, permission));

                return false;
            }
            return true;
        }

        private void VerifyNotOnMainThread()
        {
            Looper looper = Looper.MyLooper();
            if (looper != null && looper == _androidContext.MainLooper)
            {
                Exception exception = new MsalException(MsalErrorMessage.CallingThisFromTheMainThreadCanLeadToDeadlock);
                _serviceBundle.DefaultLogger.ErrorPii(exception);

                if (_androidContext.ApplicationInfo.TargetSdkVersion >= BuildVersionCodes.Froyo)
                {
                    throw exception;
                }
            }
        }

        private global::Android.Accounts.Account FindAccount(string accountName, global::Android.Accounts.Account[] accountList)
        {
            _serviceBundle.DefaultLogger.VerbosePii(AndroidBrokerConstants.BrokerProxyFindingAccount + accountName, AndroidBrokerConstants.BrokerProxyFindingAccount);

            if (accountList != null)
            {
                foreach (global::Android.Accounts.Account account in accountList)
                {
                    bool found = account != null &&
                                 account.Name != null &&
                                 account.Name.Equals(accountName, StringComparison.OrdinalIgnoreCase);

                    _serviceBundle.DefaultLogger.VerbosePii(
                        AndroidBrokerConstants.BrokerProxyAccountFoundMessage(found) + account?.Name, AndroidBrokerConstants.BrokerProxyAccountFoundMessage(found));

                    if (found)
                    {
                        return account;
                    }
                }
            }

            return null;
        }

        private IAccount FindAccountInfo(string username, IAccount[] accountList)
        {
            if (accountList != null)
            {
                foreach (IAccount account in accountList)
                {
                    if (account != null && !string.IsNullOrEmpty(account.Username)
                        && account.Username.Equals(username, StringComparison.OrdinalIgnoreCase))
                    {
                        return account;
                    }
                }
            }

            return null;
        }
        private MsalTokenResponse GetResultFromBrokerResponse(Bundle bundleResult)
        {
            if (bundleResult == null)
            {
                throw new MsalException(MsalErrorMessage.BundleResultInBrokerResponseIsNull);
            }

            int errCode = bundleResult.GetInt(AccountManager.KeyErrorCode);
            string msg = bundleResult.GetString(AccountManager.KeyErrorMessage);
            if (!string.IsNullOrEmpty(msg))
            {
                throw new MsalException(errCode.ToString(CultureInfo.InvariantCulture), msg);
            }
            else
            {
                bool initialRequest = bundleResult.ContainsKey(AndroidBrokerConstants.AccountInitialRequest);
                if (initialRequest)
                {
                    // Initial request from app to Authenticator needs to launch
                    // prompt. null resultEx means initial request
                    _serviceBundle.DefaultLogger.Info(AndroidBrokerConstants.BrokerProxyInitialRequestNotReturningAToken);
                    return null;
                }

                // IDtoken is not present in the current broker user model
                AdalUserInfo adalUserinfo = GetUserInfoFromBrokerResult(bundleResult);
                AdalResult result =
                    new AdalResult(BrokerResponseConst.Bearer, bundleResult.GetString(AccountManager.KeyAuthtoken),
                        ConvertFromTimeT(bundleResult.GetLong(AndroidBrokerConstants.AccountExpireDate, 0)))
                    {
                        UserInfo = adalUserinfo
                    };

                result.UpdateTenantAndUserInfo(bundleResult.GetString(AndroidBrokerConstants.AccountUserInfoTenantId), null,
                    adalUserinfo);

                return new MsalTokenResponse
                {
                    Result = result,
                    RefreshToken = null,
                    ResourceInResponse = null,
                };
            }
        }

        internal static DateTimeOffset ConvertFromTimeT(long seconds)
        {
            var startTime = new DateTimeOffset(1970, 1, 1, 0, 0, 0, 0, TimeSpan.Zero);
            return startTime.AddMilliseconds(seconds);
        }


        private static AdalUserInfo GetUserInfoFromBrokerResult(Bundle bundle)
        {
            // Broker has one user and related to ADFS WPJ user. It does not return
            // idtoken
            string userid = bundle.GetString(AndroidBrokerConstants.AccountUserInfoUserId);
            string givenName = bundle
                .GetString(AndroidBrokerConstants.AccountUserInfoGivenName);
            string familyName = bundle
                .GetString(AndroidBrokerConstants.AccountUserInfoFamilyName);
            string identityProvider = bundle
                .GetString(AndroidBrokerConstants.AccountUserInfoIdentityProvider);
            string displayableId = bundle
                .GetString(AndroidBrokerConstants.AccountUserInfoUserIdDisplayable);
            return new AdalUserInfo
            {
                UniqueId = userid,
                GivenName = givenName,
                FamilyName = familyName,
                IdentityProvider = identityProvider,
                DisplayableId = displayableId
            };
        }


        private string GetRedirectUriForBroker()
        {
            string packageName = Application.Context.PackageName;

            // First available signature. Applications can be signed with multiple
            // signatures.
            string signatureDigest = this.GetCurrentSignatureForPackage(packageName);
            if (!string.IsNullOrEmpty(signatureDigest))
            {
                return string.Format(CultureInfo.InvariantCulture, "{0}://{1}/{2}", RedirectUriScheme,
                    packageName.ToLowerInvariant(), signatureDigest);
            }

            return string.Empty;
        }

        private string GetCurrentSignatureForPackage(string packageName)
        {
            try
            {
                PackageInfo info = Application.Context.PackageManager.GetPackageInfo(packageName,
                    PackageInfoFlags.Signatures);
                if (info != null && info.Signatures != null && info.Signatures.Count > 0)
                {
                    Signature signature = info.Signatures[0];
                    MessageDigest md = MessageDigest.GetInstance(AndroidBrokerConstants.SHA);
                    md.Update(signature.ToByteArray());
                    return Convert.ToBase64String(md.Digest(), Base64FormattingOptions.None);
                    // Server side needs to register all other tags. MSAL will
                    // send one of them.
                }
            }
            catch (PackageManager.NameNotFoundException)
            {
                _serviceBundle.DefaultLogger.Info(AndroidBrokerConstants.CallingAppPackageDoesNotExistInPackageManager);
            }
            catch (NoSuchAlgorithmException)
            {
                _serviceBundle.DefaultLogger.Info(AndroidBrokerConstants.DigestShaAlgorithmDoesNotExist);
            }

            return null;
        }

        private Bundle GetBrokerOptions(AndroidBrokerAuthenticationRequest brokerAuthenticationRequest)
        {
            Bundle brokerOptions = new Bundle();
            // request needs to be parcelable to send across process
            brokerOptions.PutInt("com.microsoft.aad.adal:RequestId", brokerAuthenticationRequest.RequestId);
            brokerOptions.PutString(AndroidBrokerConstants.AccountAuthority,
                brokerAuthenticationRequest.Authority);
            brokerOptions.PutInt("json", 1);
            brokerOptions.PutString(AndroidBrokerConstants.AccountResource,
                brokerAuthenticationRequest.Resource);

            ValidateBrokerRedirectURI(brokerAuthenticationRequest);

            brokerOptions.PutString(AndroidBrokerConstants.AccountRedirect, brokerAuthenticationRequest.RedirectUri);
            brokerOptions.PutString(AndroidBrokerConstants.AccountClientIdKey,
                brokerAuthenticationRequest.ClientId);
            brokerOptions.PutString(AndroidBrokerConstants.AdalVersionKey,
                brokerAuthenticationRequest.Version);
            brokerOptions.PutString(AndroidBrokerConstants.AccountExtraQueryParam,
                brokerAuthenticationRequest.ExtraQueryParamsAuthentication);

            brokerOptions.PutString(AndroidBrokerConstants.CallerInfoPackage, Application.Context.PackageName);
            brokerOptions.PutInt(AndroidBrokerConstants.CallerInfoUID, Process.MyPid());

            if (brokerAuthenticationRequest.Claims != null)
            {
                brokerOptions.PutString(AndroidBrokerConstants.SkipCache, Boolean.TrueString.ToLowerInvariant());
                brokerOptions.PutString(AndroidBrokerConstants.Claims, brokerAuthenticationRequest.Claims);
            }

            if (brokerAuthenticationRequest.CorrelationId != null)
            {
                brokerOptions.PutString(AndroidBrokerConstants.AccountCorrelationId, brokerAuthenticationRequest
                    .CorrelationId.ToString());
            }

            string username = brokerAuthenticationRequest.BrokerAccountName;
            if (string.IsNullOrEmpty(username))
            {
                username = brokerAuthenticationRequest.LoginHint;
            }

            brokerOptions.PutString(AndroidBrokerConstants.AccountLoginHint, username);
            brokerOptions.PutString(AndroidBrokerConstants.AccountName, username);

            return brokerOptions;
        }

        private void ValidateBrokerRedirectURI(AndroidBrokerAuthenticationRequest brokerAuthenticationRequest)
        {
            //During the silent broker flow, the redirect URI will be null.
            if (string.IsNullOrEmpty(brokerAuthenticationRequest.RedirectUri))
            {
                return;
            }

            string computedRedirectUri = GetRedirectUriForBroker();

            if (!string.Equals(computedRedirectUri, brokerAuthenticationRequest.RedirectUri, StringComparison.OrdinalIgnoreCase))
            {
                throw new MsalException(MsalErrorAndroidEx.IncorrectBrokerRedirectUri, string.Format(CultureInfo.CurrentCulture, MsalErrorMessageAndroidEx.BrokerRedirectUriIncorrectFormat, computedRedirectUri));
            }
        }

        private bool CheckAccount(AccountManager am, string username, string uniqueId)
        {
            AuthenticatorDescription[] authenticators = am.GetAuthenticatorTypes();
            _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.BrokerProxyCheckAccountIsGettingTheAuthenticatorTypes + (authenticators?.Length ?? 0));

            foreach (AuthenticatorDescription authenticator in authenticators)
            {
                if (authenticator.Type.Equals(AndroidBrokerConstants.BrokerAccountType, StringComparison.OrdinalIgnoreCase))
                {
                    global::Android.Accounts.Account[] accountList = _androidAccountManager
                        .GetAccountsByType(AndroidBrokerConstants.BrokerAccountType);

                    _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.BrokerProxyGettingTheAccountList + (accountList?.Length ?? 0));

                    string packageName;

                    if (authenticator.PackageName
                        .Equals(AndroidBrokerConstants.AzureAuthenticatorAppPackageName, StringComparison.OrdinalIgnoreCase))
                    {
                        packageName = AndroidBrokerConstants.AzureAuthenticatorAppPackageName;
                    }
                    else if (authenticator.PackageName
                        .Equals(AndroidBrokerConstants.PackageName, StringComparison.OrdinalIgnoreCase))
                    {
                        packageName = AndroidBrokerConstants.PackageName;
                    }
                    else
                    {
                        _serviceBundle.DefaultLogger.Warning(AndroidBrokerConstants.BrokerProxyCheckingTheAccountFailedBecauseTheBrokerPackageWasNotFound);
                        return false;
                    }

                    _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.BrokerProxyPackageName + packageName);

                    if (HasSupportToAddUserThroughBroker(packageName))
                    {
                        _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.BrokerProxyBrokerSupportsAddingAccounts);
                        return true;
                    }
                    else if (accountList != null && accountList.Length > 0)
                    {
                        _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.BrokerProxyBrokerDoesNotSupportAddingAccountsButSomeAccountsAreConfiguredVerifyingIfAnAccountCanBeUsed);
                        return VerifyAccount(accountList, username, uniqueId);
                    }
                }
            }

            _serviceBundle.DefaultLogger.Warning(AndroidBrokerConstants.BrokerProxyCouldNotVerifyThatAnAccountCanBeUsed);
            return false;
        }

        private bool VerifyAccount(global::Android.Accounts.Account[] accountList, string username, string uniqueId)
        {
            _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.BrokerProxyStartingAccountVerification);

            if (!string.IsNullOrEmpty(username))
            {
                bool found = username.Equals(accountList[0].Name, StringComparison.OrdinalIgnoreCase);
                _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.BrokerProxyFoundAnAccountThatMatchesTheUsername + false);
                return found;
            }

            if (!string.IsNullOrEmpty(uniqueId))
            {
                // Uniqueid for account at authenticator is not available with
                // Account
                UserInfo[] users;
                try
                {
                    users = GetBrokerAccounts();
                    UserInfo matchingUser = FindUserInfo(uniqueId, users);
                    return matchingUser != null;
                }
                catch (Exception e)
                {
                    _serviceBundle.DefaultLogger.Error(AndroidBrokerConstants.BrokerProxyCouldNotVerifyAnAccountBecauseOfAnException);
                    _serviceBundle.DefaultLogger.ErrorPii(e);
                }

                _serviceBundle.DefaultLogger.Warning(AndroidBrokerConstants.BrokerProxyCouldNotVerifyTheAccount);

                return false;
            }

            // if username or uniqueid are not specified, it should use the broker
            // account.
            _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.BrokerProxyAccountVerificationPassed);
            return true;
        }

        private bool HasSupportToAddUserThroughBroker(string packageName)
        {
            Intent intent = new Intent();
            intent.SetPackage(packageName);
            intent.SetClassName(packageName, packageName + AndroidBrokerConstants.AccountChooserActivity);

            PackageManager packageManager = _androidContext.PackageManager;
            IList<ResolveInfo> infos = packageManager.QueryIntentActivities(intent, 0);
            return infos.Count > 0;
        }

        private bool VerifySignature(string brokerPackageName)
        {
            List<X509Certificate2> certs = ReadCertDataForBrokerApp(brokerPackageName);

            VerifySignatureHash(certs);
            if (certs.Count > 1)
            {
                // Verify the certificate chain is chained correctly.
                VerifyCertificateChain(certs);
            }

            return true;
        }

        private void VerifySignatureHash(List<X509Certificate2> certs)
        {
            bool validSignatureFound = false;

            foreach (var signerCert in certs)
            {
                MessageDigest messageDigest = MessageDigest.GetInstance("SHA");
                messageDigest.Update(signerCert.RawData);

                // Check the hash for signer cert is the same as what we hardcoded.
                string signatureHash = Base64.EncodeToString(messageDigest.Digest(), Base64Flags.NoWrap);
                if (BrokerTag.Equals(signatureHash, StringComparison.OrdinalIgnoreCase) ||
                    AndroidBrokerConstants.AzureAuthenticatorAppSignature.Equals(signatureHash, StringComparison.OrdinalIgnoreCase))
                {
                    validSignatureFound = true;
                }
            }

            if (!validSignatureFound)
            {
                throw new MsalException(MsalErrorAndroidEx.SignatureVerificationFailed, MsalErrorMessageAndroidEx.NoMatchingSignatureFound);
            }
        }

        private void VerifyCertificateChain(List<X509Certificate2> certificates)
        {
            X509Certificate2Collection collection = new X509Certificate2Collection(certificates.ToArray());
            X509Chain chain = new X509Chain();
            chain.ChainPolicy = new X509ChainPolicy()
            {
                RevocationMode = X509RevocationMode.NoCheck
            };

            chain.ChainPolicy.ExtraStore.AddRange(collection);
            foreach (X509Certificate2 certificate in certificates)
            {
                var chainBuilt = chain.Build(certificate);

                if (!chainBuilt)
                {
                    foreach (X509ChainStatus chainStatus in chain.ChainStatus)
                    {
                        if (chainStatus.Status != X509ChainStatusFlags.UntrustedRoot)
                        {
                            throw new MsalException(MsalErrorAndroidEx.SignatureVerificationFailed,
                                string.Format(CultureInfo.InvariantCulture, MsalErrorMessageAndroidEx.AppCertificateValidationFailed + chainStatus.Status));
                        }
                    }
                }
            }

        }

        private List<X509Certificate2> ReadCertDataForBrokerApp(string brokerPackageName)
        {
            PackageInfo packageInfo = _androidContext.PackageManager.GetPackageInfo(brokerPackageName,
                PackageInfoFlags.Signatures);
            if (packageInfo == null)
            {
                throw new MsalException(MsalErrorAndroidEx.SignatureVerificationFailed,
                    MsalErrorMessageAndroidEx.NoBrokerPackageFound);
            }

            if (packageInfo.Signatures == null || packageInfo.Signatures.Count == 0)
            {
                throw new MsalException(MsalErrorAndroidEx.SignatureVerificationFailed,
                    MsalErrorMessageAndroidEx.SignatureVerificationFailed);
            }

            List<X509Certificate2> certificates = new List<X509Certificate2>(packageInfo.Signatures.Count);
            foreach (Signature signature in packageInfo.Signatures)
            {
                byte[] rawCert = signature.ToByteArray();
                X509Certificate2 x509Certificate = null;
                x509Certificate = new X509Certificate2(rawCert);
                certificates.Add(x509Certificate);
            }

            return certificates;
        }

        private bool VerifyAuthenticator(AccountManager am)
        {
            // there may be multiple authenticators from same package
            // , but there is only one entry for an authenticator type in
            // AccountManager.
            // If another app tries to install same authenticator type, it will
            // queue up and will be active after first one is uninstalled.
            AuthenticatorDescription[] authenticators = am.GetAuthenticatorTypes();
            foreach (AuthenticatorDescription authenticator in authenticators)
            {
                if (authenticator.Type.Equals(AndroidBrokerConstants.BrokerAccountType, StringComparison.OrdinalIgnoreCase)
                    && VerifySignature(authenticator.PackageName))
                {
                    _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.BrokerProxyFoundTheAuthenticatorOnTheDevice);
                    return true;
                }
            }

            _serviceBundle.DefaultLogger.Warning(AndroidBrokerConstants.BrokerProxyNoAuthenticatorFoundOnTheDevice);
            return false;
        }


        private IAccount[] GetBrokerAccounts()
        {
            // Calling this on main thread will cause an exception since this is
            // waiting on AccountManagerFuture
            if (Looper.MyLooper() == Looper.MainLooper)
            {
                throw new MsalException(MsalErrorAndroidEx.CallingOnMainThread);
            }

            global::Android.Accounts.Account[] accountList = _androidAccountManager
                .GetAccountsByType(AndroidBrokerConstants.BrokerAccountType);
            Bundle bundle = new Bundle();
            bundle.PutBoolean(WorkAccount, true);

            if (accountList != null)
            {
                // get info for each user
                UserInfo[] users = new UserInfo[accountList.Length];
                for (int i = 0; i < accountList.Length; i++)
                {
                    // Use AccountManager Api method to get extended user info
                    IAccountManagerFuture result = _androidAccountManager.UpdateCredentials(
                        accountList[i], AndroidBrokerConstants.AuthtokenType, bundle,
                        null, null, null);

                    _serviceBundle.DefaultLogger.Verbose("Waiting for the result");

                    Bundle userInfoBundle = (Bundle)result.Result;

                    users[i] = new UserInfo
                    {
                        UniqueId = userInfoBundle
                            .GetString(AndroidBrokerConstants.AccountUserInfoUserId),
                        GivenName = userInfoBundle
                            .GetString(AndroidBrokerConstants.AccountUserInfoGivenName),
                        FamilyName = userInfoBundle
                            .GetString(AndroidBrokerConstants.AccountUserInfoFamilyName),
                        IdentityProvider = userInfoBundle
                            .GetString(AndroidBrokerConstants.AccountUserInfoIdentityProvider),
                        DisplayableId = userInfoBundle
                            .GetString(AndroidBrokerConstants.AccountUserInfoUserIdDisplayable),
                    };
                }

                return users;
            }
            return null;
        }
    }
}
