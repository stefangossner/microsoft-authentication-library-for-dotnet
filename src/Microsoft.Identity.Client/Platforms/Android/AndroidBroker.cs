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

using Microsoft.Identity.Client.Internal.Broker;
using Android.App;
using Android.Content;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Identity.Client.ApiConfig;
using Microsoft.Identity.Client.OAuth2;
using System.Threading;
using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.Utils;

namespace Microsoft.Identity.Client.Platforms.Android
{
    /// <summary>
    /// Handles requests which invoke the broker. This is only for mobile (iOS and Android) scenarios.
    /// </summary>
    [global::Android.Runtime.Preserve(AllMembers = true)]
    internal class AndroidBroker : IBroker
    {
        private static SemaphoreSlim readyForResponse = null;
        private IServiceBundle _serviceBundle;
        private readonly AndroidBrokerProxy _brokerProxy;
        private MsalTokenResponse _msalTokenResponse = null;
        OwnerUiParent _uiParent;

        public AndroidBroker(IServiceBundle serviceBundle)
        {
            _serviceBundle = serviceBundle;
            _brokerProxy = new AndroidBrokerProxy(Application.Context, _serviceBundle);
        }

        public bool CanInvokeBroker(OwnerUiParent uiParent)
        {
            if (!_serviceBundle.Config.IsBrokerEnabled)
            {
                return false;
            }

            bool canInvoke = _brokerProxy.CanSwitchToBroker();
            _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.CanInvokeBroker + canInvoke);
            _uiParent = uiParent;
            return canInvoke;
        }

        public async Task<MsalTokenResponse> AcquireTokenUsingBrokerAsync(Dictionary<string, string> brokerPayload)
        {
            readyForResponse = new SemaphoreSlim(0);
            try
            {
                await Task.Run(() => AcquireTokenInternal(brokerPayload)).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _serviceBundle.DefaultLogger.ErrorPii(ex);
                throw;
            }
            await readyForResponse.WaitAsync().ConfigureAwait(false);
            return _msalTokenResponse;
        }

        private void AcquireTokenInternal(IDictionary<string, string> brokerPayload)
        {
            if (brokerPayload.ContainsKey(BrokerParameter.BrokerInstallUrl))
            {
                _serviceBundle.DefaultLogger.Info(AndroidBrokerConstants.AndroidBrokerPayloadContainsInstallUrl);

                string url = brokerPayload[BrokerParameter.BrokerInstallUrl];
                Uri uri = new Uri(url);
                string query = uri.Query;
                if (query.StartsWith("?", StringComparison.OrdinalIgnoreCase))
                {
                    query = query.Substring(1);
                }

                Dictionary<string, string> keyPair = CoreHelpers.ParseKeyValueList(query, '&', true, false, null);

                var appLink = keyPair[BrokerParameter.AppLink];
                _serviceBundle.DefaultLogger.Info(AndroidBrokerConstants.AndroidBrokerStartingActionViewActivityTo + appLink);
                _uiParent.CoreUiParent.CallerActivity.StartActivity(new Intent(Intent.ActionView, global::Android.Net.Uri.Parse(appLink)));

                throw new MsalException(MsalErrorAndroidEx.BrokerApplicationRequired, MsalErrorMessageAndroidEx.BrokerApplicationRequired);
            }

            Context mContext = Application.Context;
            AndroidBrokerAuthenticationRequest brokerAuthenticationRequest = new AndroidBrokerAuthenticationRequest(brokerPayload);

            // BROKER flow intercepts here
            // cache and refresh call happens through the authenticator service
            if (_brokerProxy.VerifyUser(brokerAuthenticationRequest.LoginHint,
                brokerAuthenticationRequest.UserId))
            {

                brokerAuthenticationRequest.BrokerAccountName = brokerAuthenticationRequest.LoginHint;
                _serviceBundle.DefaultLogger.InfoPii(
                    AndroidBrokerConstants.SwitchedToBrokerForContext + mContext.PackageName + AndroidBrokerConstants.LoginHint + brokerAuthenticationRequest.BrokerAccountName,
                    AndroidBrokerConstants.SwitchedToBrokerForContext);

                // Don't send background request, if prompt flag is always or
                // refresh_session
                bool hasAccountNameOrUserId = !string.IsNullOrEmpty(brokerAuthenticationRequest.BrokerAccountName) || !string.IsNullOrEmpty(brokerAuthenticationRequest.UserId);
                if (string.IsNullOrEmpty(brokerAuthenticationRequest.Claims) && hasAccountNameOrUserId)
                {
                    _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.UserIsSpecifiedForBackgroundTokenRequest);
                    _msalTokenResponse = _brokerProxy.GetAuthTokenInBackground(brokerAuthenticationRequest, _uiParent.CoreUiParent.CallerActivity);
                }
                else
                {
                    _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.UserIsNotSpecifiedForBackgroundTokenRequest);
                }

                if (_msalTokenResponse != null && !string.IsNullOrEmpty(_msalTokenResponse.AccessToken))
                {
                    _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.TokenIsReturnedFromBackgroundCall);
                    readyForResponse.Release();
                    return;
                }

                // Launch broker activity
                // if cache and refresh request is not handled.
                // Initial request to authenticator needs to launch activity to
                // record calling uid for the account. This happens for Prompt auto
                // or always behavior.
                // Only happens with callback since silent call does not show UI
                _serviceBundle.DefaultLogger.Verbose(AndroidBrokerConstants.TokenIsNotReturnedFromBackgroundCallLaunchActivityForAuthenticator);

                if (_msalTokenResponse == null)
                {
                    _serviceBundle.DefaultLogger.Verbose("Initial request to authenticator");
                    // Log the initial request but not force a prompt
                }

                if (brokerPayload.ContainsKey(BrokerParameter.SilentBrokerFlow))
                {
                    _serviceBundle.DefaultLogger.Error(AndroidBrokerConstants.CannotInvokeBrokerInInteractiveModeBecauseThisIsASilentFlow);
                    throw new MsalUiRequiredException(MsalError.FailedToAcquireTokenSilentlyFromBroker, AndroidBrokerConstants.CannotInvokeBrokerInInteractiveModeBecauseThisIsASilentFlow);
                }

                // onActivityResult will receive the response
                // Activity needs to launch to record calling app for this
                // account
                Intent brokerIntent = _brokerProxy.GetIntentForBrokerActivity(brokerAuthenticationRequest, _uiParent.CoreUiParent.CallerActivity);
                if (brokerIntent != null)
                {
                    try
                    {
                        _serviceBundle.DefaultLogger.Verbose(
                            AndroidBrokerConstants.CallingActivityPid + global::Android.OS.Process.MyPid()
                            + AndroidBrokerConstants.tid + global::Android.OS.Process.MyTid() 
                            + AndroidBrokerConstants.uid + global::Android.OS.Process.MyUid());

                        _uiParent.CoreUiParent.CallerActivity.StartActivityForResult(brokerIntent, 1001);
                    }
                    catch (ActivityNotFoundException e)
                    {
                        _serviceBundle.DefaultLogger.ErrorPii(e);
                    }
                }
            }
            else
            {
                throw new MsalException(MsalErrorAndroidEx.NoBrokerAccountFound, MsalErrorMessageAndroidEx.AddRequestedAccountOrSetUseBroker);
            }
        }

        internal MsalTokenResponse SetBrokerResult(Intent data, int resultCode)
        {

            if (resultCode != BrokerResponseConst.ResponseReceived)
            {
                throw new MsalException(data.GetStringExtra(AndroidBrokerConstants.ResponseErrorCode),
                            data.GetStringExtra(AndroidBrokerConstants.ResponseErrorMessage));
            }
            else
            {
                _msalTokenResponse = new MsalTokenResponse
                {
                    Authority = data.GetStringExtra(AndroidBrokerConstants.AccountAuthority),
                    AccessToken = data.GetStringExtra(AndroidBrokerConstants.AccountAccessToken),
                    IdToken = data.GetStringExtra(AndroidBrokerConstants.AccountIdToken),
                    TokenType = "Bearer",
                    ExpiresIn = data.GetLongExtra(AndroidBrokerConstants.AccountExpireDate, 0)
                };
            }

            readyForResponse.Release();

            return _msalTokenResponse;
        }
    }
}