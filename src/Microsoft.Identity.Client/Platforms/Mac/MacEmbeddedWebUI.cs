// ------------------------------------------------------------------------------
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
// ------------------------------------------------------------------------------

using Foundation;
using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.Exceptions;
using Microsoft.Identity.Client.Extensibility;
using Microsoft.Identity.Client.Http;
using Microsoft.Identity.Client.UI;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Identity.Client.Platforms.Mac
{
    internal class MacEmbeddedWebUI : IWebUI
    {
        private SemaphoreSlim _returnedUriReady;
        private AuthorizationResult _authorizationResult;
        private readonly RequestContext _requestContext;
        private readonly CoreUIParent _coreUIParent;

        public MacEmbeddedWebUI(CoreUIParent coreUIParent, RequestContext requestContext)
        {
            _requestContext = requestContext;
            _coreUIParent = coreUIParent;
        }

        public async Task<Uri> AcquireAuthorizationAsync(
            Uri authorizationUri, 
            Uri redirectUri, 
            CancellationToken cancellationToken)
        {
            _returnedUriReady = new SemaphoreSlim(0);
            Authenticate(authorizationUri, redirectUri);

            await _returnedUriReady.WaitAsync(cancellationToken).ConfigureAwait(false);

            return _authorizationResult;
        }

        private void SetAuthorizationResult(AuthorizationResult authorizationResultInput)
        {
            _authorizationResult = authorizationResultInput;
            _returnedUriReady.Release();
        }

        private void Authenticate(Uri authorizationUri, Uri redirectUri)
        {
            try
            {
                // Ensure we create the NSViewController on the main thread.
                // Consumers of our library must ensure they do not block the main thread
                // or else they will cause a deadlock.
                // For example calling `AcquireTokenAsync(...).Result` from the main thread
                // would result in this delegate never executing.
                NSRunLoop.Main.BeginInvokeOnMainThread(() =>
                {
                    var windowController = new AuthenticationAgentNSWindowController(
                        authorizationUri.AbsoluteUri,
                        redirectUri.OriginalString,
                        SetAuthorizationResult);

                    windowController.Run(_coreUIParent.CallerWindow);
                });
            }
            catch (Exception ex)
            {
                throw new MsalClientException(
                    CoreErrorCodes.AuthenticationUiFailed,
                    "See inner exception for details",
                    ex);
            }
        }

        public void ValidateRedirectUri(Uri redirectUri)
        {
            RedirectUriHelper.Validate(redirectUri, usesSystemBrowser: false);
        }
    }
}
