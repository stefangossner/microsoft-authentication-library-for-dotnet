﻿//----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.IdentityModel.Clients.ActiveDirectory
{
    /// <summary>
    /// The encoding helper.
    /// </summary>
    internal static class EncodingHelper
    {

        public static string UrlEncode(string message)
        {
            if (string.IsNullOrEmpty(message))
            {
                return message;
            }

            message = Uri.EscapeDataString(message);
            message = message.Replace("%20", "+");

            return message;
        }

        public static string UrlDecode(string message)
        {
            if (string.IsNullOrEmpty(message))
            {
                return message;
            }

            message = message.Replace("+", "%20");
            message = Uri.UnescapeDataString(message);

            return message;
        }

        public static void AddKeyValueString(StringBuilder messageBuilder, string key, string value)
        {
            AddKeyValueString(messageBuilder, key, value.ToCharArray());
        }

        public static string ToQueryParameter(this IDictionary<string, string> input)
        {
            StringBuilder builder = new StringBuilder();
            foreach (var key in input.Keys)
            {
                builder.AppendFormat("{0}={1}&", key, UrlEncode(input[key]));
            }

            builder.Remove(builder.Length - 1, 1);
            return builder.ToString();
        }

        public static Dictionary<string, string> ParseKeyValueList(string input, char delimiter, bool urlDecode, CallState callState)
        {
            var response = new Dictionary<string, string>();

            List<string> queryPairs = SplitWithQuotes(input, delimiter);

            foreach (string queryPair in queryPairs)
            {
                List<string> pair = SplitWithQuotes(queryPair, '=');

                if (pair.Count == 2 && !string.IsNullOrWhiteSpace(pair[0]) && !string.IsNullOrWhiteSpace(pair[1]))
                {
                    string key = pair[0];
                    string value = pair[1];

                    // Url decoding is needed for parsing OAuth response, but not for parsing WWW-Authenticate header in 401 challenge
                    if (urlDecode)
                    {
                        key = UrlDecode(key);
                        value = UrlDecode(value);
                    }

                    key = key.Trim().ToLower();
                    value = value.Trim().Trim(new[] { '\"' }).Trim();

                    if (response.ContainsKey(key))
                    {
                        PlatformPlugin.Logger.Warning(callState, string.Format("Key/value pair list contains redundant key '{0}'.", key));
                    }

                    response[key] = value;
                }
            }

            return response;
        }

        public static byte[] ToByteArray(this String stringInput)
        {
            return ToByteArray(new StringBuilder(stringInput));
        }

        public static byte[] ToByteArray(this StringBuilder stringBuilder)
        {
            if (stringBuilder == null)
            {
                return null;
            }

            UTF8Encoding encoding = new UTF8Encoding();
            var messageChars = new char[stringBuilder.Length];

            try
            {
                stringBuilder.CopyTo(0, messageChars, 0, stringBuilder.Length);
                return encoding.GetBytes(messageChars);
            }
            finally
            {
                messageChars.SecureClear();
            }
        }

        public static void SecureClear(this StringBuilder stringBuilder)
        {
            if (stringBuilder != null)
            {
                for (int i = 0; i < stringBuilder.Length; i++)
                {
                    stringBuilder[i] = '\0';
                }

                stringBuilder.Length = 0;
            }
        }

        public static void SecureClear(this byte[] bytes)
        {
            if (bytes != null)
            {
                for (int i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = 0;
                }
            }
        }

        public static void SecureClear(this char[] chars)
        {
            if (chars != null)
            {
                for (int i = 0; i < chars.Length; i++)
                {
                    chars[i] = '\0';
                }
            }
        }

        internal static string Base64Encode(string input)
        {
            string encodedString = String.Empty;
            if (!String.IsNullOrEmpty(input))
            {
                encodedString = Convert.ToBase64String(Encoding.UTF8.GetBytes(input));
            }

            return encodedString;
        }

        internal static string Base64Decode(string encodedString)
        {
            string output = null;
            if (!String.IsNullOrEmpty(encodedString))
            {
                byte[] outputBytes = Convert.FromBase64String(encodedString);
                output = Encoding.UTF8.GetString(outputBytes, 0, outputBytes.Length);
            }

            return output;
        }

        internal static char[] UrlEncode(char[] message)
        {
            if (message == null)
            {
                return null;
            }

            var encodedMessage = new char[message.Length * 2];
            int length = 0;
            var singleChar = new char[1];
            foreach (char ch in message)
            {
                singleChar[0] = ch;
                var str = new string(singleChar);
                string encodedStr = UrlEncode(str);
                char[] encodedSingleChar = encodedStr.ToCharArray();
                encodedSingleChar.CopyTo(encodedMessage, length);
                if (length + encodedSingleChar.Length > encodedMessage.Length)
                {
                    Array.Resize(ref encodedMessage, message.Length * 2);
                }

                length += encodedSingleChar.Length;
            }

            Array.Resize(ref encodedMessage, length);
            return encodedMessage;
        }

        internal static List<string> SplitWithQuotes(string input, char delimiter)
        {
            List<string> items = new List<string>();

            if (string.IsNullOrWhiteSpace(input))
            {
                return items;
            }

            int startIndex = 0;
            bool insideString = false;
            string item;
            for (int i = 0; i < input.Length; i++)
            {
                if (input[i] == delimiter && !insideString)
                {
                    item = input.Substring(startIndex, i - startIndex);
                    if (!string.IsNullOrWhiteSpace(item.Trim()))
                    {
                        items.Add(item);
                    }

                    startIndex = i + 1;
                }
                else if (input[i] == '"')
                {
                    insideString = !insideString;
                }
            }

            item = input.Substring(startIndex);
            if (!string.IsNullOrWhiteSpace(item.Trim()))
            {
                items.Add(item);
            }

            return items;
        }

        private static void AddKeyValueString(StringBuilder messageBuilder, string key, char[] value)
        {
            string delimiter = (messageBuilder.Length == 0) ? string.Empty : "&";
            messageBuilder.AppendFormat("{0}{1}=", delimiter, key);
            messageBuilder.Append(value);
        }

        internal static string GetString(byte[] bytes)
        {
            char[] chars = new char[bytes.Length / sizeof(char)];
            System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }
    }
}
