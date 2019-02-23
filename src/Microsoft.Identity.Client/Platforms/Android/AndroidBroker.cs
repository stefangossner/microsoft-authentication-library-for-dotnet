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
            _serviceBundle.DefaultLogger.Verbose("Can invoke broker? " + canInvoke);
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
                _serviceBundle.DefaultLogger.Info("Android Broker - broker payload contains install url");

                string url = brokerPayload[BrokerParameter.BrokerInstallUrl];
                Uri uri = new Uri(url);
                string query = uri.Query;
                if (query.StartsWith("?", StringComparison.OrdinalIgnoreCase))
                {
                    query = query.Substring(1);
                }

                Dictionary<string, string> keyPair = CoreHelpers.ParseKeyValueList(query, '&', true, false, null);

                var appLink = keyPair["app_link"];
                _serviceBundle.DefaultLogger.Info("Android Broker - Starting ActionView activity to " + appLink);
                _uiParent.CoreUiParent.CallerActivity.StartActivity(new Intent(Intent.ActionView, Android.Net.Uri.Parse(appLink)));

                throw new MsalException(AdalErrorAndroidEx.BrokerApplicationRequired, AdalErrorMessageAndroidEx.BrokerApplicationRequired);
            }

            Context mContext = Application.Context;
            AuthenticationRequest request = new AuthenticationRequest(brokerPayload);

            // BROKER flow intercepts here
            // cache and refresh call happens through the authenticator service
            if (_brokerProxy.VerifyUser(request.LoginHint,
                request.UserId))
            {

                request.BrokerAccountName = request.LoginHint;
                _serviceBundle.DefaultLogger.InfoPii(
                    "It switched to broker for context: " + mContext.PackageName + " login hint: " + request.BrokerAccountName,
                    "It switched to broker for context");

                // Don't send background request, if prompt flag is always or
                // refresh_session
                bool hasAccountNameOrUserId = !string.IsNullOrEmpty(request.BrokerAccountName) || !string.IsNullOrEmpty(request.UserId);
                if (string.IsNullOrEmpty(request.Claims) && hasAccountNameOrUserId)
                {
                    _serviceBundle.DefaultLogger.Verbose("User is specified for background token request");
                    _msalTokenResponse = _brokerProxy.GetAuthTokenInBackground(request, _uiParent.CoreUiParent.CallerActivity);
                }
                else
                {
                    _serviceBundle.DefaultLogger.Verbose("User is not specified for background token request");
                }

                if (_msalTokenResponse != null && !string.IsNullOrEmpty(_msalTokenResponse.AccessToken))
                {
                    _serviceBundle.DefaultLogger.Verbose("Token is returned from background call");
                    readyForResponse.Release();
                    return;
                }

                // Launch broker activity
                // if cache and refresh request is not handled.
                // Initial request to authenticator needs to launch activity to
                // record calling uid for the account. This happens for Prompt auto
                // or always behavior.
                _serviceBundle.DefaultLogger.Verbose("Token is not returned from backgroud call");

                // Only happens with callback since silent call does not show UI
                _serviceBundle.DefaultLogger.Verbose("Launch activity for Authenticator");

                _serviceBundle.DefaultLogger.Verbose("Starting Authentication Activity");

                if (_msalTokenResponse == null)
                {
                    _serviceBundle.DefaultLogger.Verbose("Initial request to authenticator");
                    // Log the initial request but not force a prompt
                }

                if (brokerPayload.ContainsKey(BrokerParameter.SilentBrokerFlow))
                {
                    _serviceBundle.DefaultLogger.Error("Can't invoke the broker in interactive mode because this is a silent flow");
                    throw new AdalSilentTokenAcquisitionException();
                }

                // onActivityResult will receive the response
                // Activity needs to launch to record calling app for this
                // account
                Intent brokerIntent = _brokerProxy.GetIntentForBrokerActivity(request, _uiParent.CoreUiParent.CallerActivity);
                if (brokerIntent != null)
                {
                    try
                    {
                        _serviceBundle.DefaultLogger.Verbose(
                            "Calling activity pid:" + Android.OS.Process.MyPid()
                            + " tid:" + Android.OS.Process.MyTid() + "uid:"
                            + Android.OS.Process.MyUid());

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
                throw new MsalException(AdalErrorAndroidEx.NoBrokerAccountFound, "Add requested account as a Workplace account via Settings->Accounts or set UseBroker=true.");
            }
        }

        internal MsalTokenResponse SetBrokerResult(Intent data, int resultCode)
        {
            if (resultCode != BrokerResponseConst.ResponseReceived)
            {
                _msalTokenResponse = new MsalTokenResponse
                {
                    Exception =
                        new MsalException(data.GetStringExtra(AndroidBrokerConstants.ResponseErrorCode),
                            data.GetStringExtra(AndroidBrokerConstants.ResponseErrorMessage))
                };
            }
            else
            {
                var tokenResponse = new MsalTokenResponse
                {
                    Authority = data.GetStringExtra(AndroidBrokerConstants.AccountAuthority),
                    AccessToken = data.GetStringExtra(AndroidBrokerConstants.AccountAccessToken),
                    IdTokenString = data.GetStringExtra(AndroidBrokerConstants.AccountIdToken),
                    TokenType = "Bearer",
                    ExpiresOn = data.GetLongExtra(AndroidBrokerConstants.AccountExpireDate, 0)
                };

                _msalTokenResponse = tokenResponse.GetResult(AndroidBrokerProxy.ConvertFromTimeT(tokenResponse.ExpiresOn),
                    AndroidBrokerProxy.ConvertFromTimeT(tokenResponse.ExpiresOn));
            }

            readyForResponse.Release();

            return _msalTokenResponse;
        }
    }
}
