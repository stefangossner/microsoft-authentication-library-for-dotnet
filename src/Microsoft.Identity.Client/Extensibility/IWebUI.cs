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
using System.Threading.Tasks;
using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.UI;

namespace Microsoft.Identity.Client.Extensibility
{
    /// <summary>
    /// Interface that an MSAL.NET extender can implement to provide their own Web UI in public client applications,
    /// to sign-in a user and have them consented part of the Authorization code flow.
    /// </summary>
    /// <remarks>
    /// MSAL.NET itself uses this interface for hosting the browser in embedded views or for calling system browsers. 
    /// It also uses it for end to end testing by injecting a Selenium controlled browser. 
    /// </remarks>
    public interface IWebUI
    {
        /// <summary>
        ///     Method called by MSAL.NET to delegate the authentication code Http conversation with the server (STS)
        /// </summary>
        /// <param name="authorizationUri">
        ///     URI computed by MSAL.NET that will let the UI extension
        ///     navigate to the STS authorization endpoint in order to sign-in the user and have them consent
        /// </param>
        /// <param name="redirectUri">The redirect Uri which was configured when constructing the <see cref="PublicClientApplication"/>
        /// Not all implementers of this interface require this information.
        /// </param>
        /// 
        /// <returns>
        ///     The URI returned back from the STS authorization endpoint. This URI contains a code=CODE
        ///     parameters that MSAL.NET will extract.
        /// </returns>
        /// <remarks>
        ///     The authorizationUri is crafted to leverage the PKCE standard - https://oauth.net/2/pkce/
        ///     in order to protect the token from a manin the middle attack. 
        ///     Only MSAL.NET can redeem the code.
        ///     
        ///     //TODO bogavril - add details about exceptions to be thrown
        /// </remarks>
        Task<AuthorizationResult> AcquireAuthorizationAsync(Uri authorizationUri, Uri redirectUri); //TODO: bogavril - add cancellation token?

        /// <summary>
        /// Method called by MSAL.NET to validate the redirect URI passed when constructing the <see cref="PublicClientApplication"/>
        /// Not all implementations of this interface require a redirect uri, so 
        /// </summary>
        /// <remarks>Implementers should return </remarks>
        void ValidateRedirectUri(Uri redirectUri);
    }
}
