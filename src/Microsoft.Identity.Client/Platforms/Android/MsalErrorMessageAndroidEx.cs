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

namespace Microsoft.Identity.Client.Platforms.Android
{
    internal static class MsalErrorMessageAndroidEx
    {
        public const string MissingPackagePermissionTemplate = "Permission {0} is missing from package manifest";
        public const string CannotSwitchToBrokerFromThisApp = "Cannot switch to broker from this app";
        public const string IncorrectBrokerAccountType = "Incorrect broker account type";
        public const string IncorrectBrokerAppSignate = "Incorrect broker app signature";
        public const string FailedToGetBrokerAppSignature = "Failed to get broker app signature";
        public const string MissingBrokerRelatedPackage = "Broker related package does not exist";
        public const string MissingDigestShaAlgorithm = "Digest SHA algorithm does not exist";
        public const string SignatureVerificationFailed = "Error in verifying broker app's signature. No signature associated with the broker package.";
        public const string NoBrokerAccountFound = "No account found in broker app";
        public const string BrokerApplicationRequired = "Broker application must be installed to continue authentication";
        public const string BrokerRedirectUriIncorrectFormat = "The broker redirect URI is incorrect. Please visit https://aka.ms/msal-net-broker-redirect-uri-android for more details. The redirect uri should be: ";
        public const string NoMatchingSignatureFound = "No matching signature found";
        public const string AppCertificateValidationFailed = "App certificate validation failed with: ";
        public const string NoBrokerPackageFound = "No broker package found.";
        public const string AddRequestedAccountOrSetUseBroker = "Add requested account as a Workplace account via Settings->Accounts or set UseBroker=true.";
    }
}
