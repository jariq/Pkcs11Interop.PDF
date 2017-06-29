/*
 *  Pkcs11Interop.PDF - Integration layer for Pkcs11Interop 
 *                      and iText (iTextSharp) libraries
 *  Copyright (c) 2013-2017 JWC s.r.o. <http://www.jwc.sk>
 *  Author: Jaroslav Imrich <jimrich@jimrich.sk>
 *
 *  Licensing for open source projects:
 *  Pkcs11Interop.PDF is available under the terms of the GNU Affero General 
 *  Public License version 3 as published by the Free Software Foundation.
 *  Please see <http://www.gnu.org/licenses/agpl-3.0.html> for more details.
 *
 *  Licensing for other types of projects:
 *  Pkcs11Interop.PDF is available under the terms of flexible commercial license.
 *  Please contact JWC s.r.o. at <info@pkcs11interop.net> for more details.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using Net.Pkcs11Interop.Common;
using NUnit.Framework;
using Org.BouncyCastle.Crypto;

namespace Net.Pkcs11Interop.PDF.Tests
{
    [TestFixture()]
    public class Pkcs11ExplorerTest
    {
        #region Settings

        /// <summary>
        /// Path to the unmanaged PCKS#11 library
        /// </summary>
        public const string _libraryPath = @"siecap11.dll";

        /// <summary>
        /// Serial number of the token that contains signing key. May be null if tokenLabel is specified.
        /// </summary>
        public const string _tokenSerial = @"7BFF2737350B262C";

        /// <summary>
        /// Label of of the token that contains signing key. May be null if tokenSerial is specified
        /// </summary>
        public const string _tokenLabel = @"Pkcs11Interop";

        /// <summary>
        /// PIN for the token
        /// </summary>
        public const string _pin = @"11111111";

        /// <summary>
        /// Label (value of CKA_LABEL attribute) of the private key used for signing. May be null if ckaId is specified.
        /// </summary>
        public const string _ckaLabel = @"John Doe";

        /// <summary>
        /// Hex encoded string with identifier (value of CKA_ID attribute) of the private key used for signing. May be null if ckaLabel is specified.
        /// </summary>
        public const string _ckaId = @"73006233654C4C88A21555CC882AFA58";

        /// <summary>
        /// Incorrect string
        /// </summary>
        public const string _incorrectString = @"aabbccddeeff";

        #endregion

        /// <summary>
        /// Tests constructor of Pkcs11Explorer class
        /// </summary>
        [Test()]
        public void ConstructorTest()
        {
            // Existing PKCS#11 library
            using (Pkcs11Explorer pkcs11Explorer = new Pkcs11Explorer(_libraryPath))
                Assert.IsTrue(pkcs11Explorer != null);

            // Non-existing PKCS#11 library
            try
            {
                Pkcs11Explorer pkcs11Explorer = new Pkcs11Explorer(_incorrectString);
                pkcs11Explorer.Dispose();
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is UnmanagedException);
            }

            // Unspecified PKCS#11 library
            try
            {
                Pkcs11Explorer pkcs11Explorer = new Pkcs11Explorer(null);
                pkcs11Explorer.Dispose();
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentNullException);
            }
        }

        /// <summary>
        /// Tests GetTokens method of Pkcs11Explorer class
        /// </summary>
        [Test()]
        public void GetTokensTest()
        {
            using (Pkcs11Explorer pkcs11Explorer = new Pkcs11Explorer(_libraryPath))
            {
                List<Token> tokens = pkcs11Explorer.GetTokens();
                Assert.IsTrue(tokens != null && tokens.Count > 0);

                bool tokenFound = false;

                for (int i = 0; i < tokens.Count; i++)
                {
                    if ((tokens[i].SerialNumber == _tokenSerial) && (tokens[i].Label == _tokenLabel))
                        tokenFound = true;

                    Assert.IsFalse(string.IsNullOrEmpty(tokens[i].ManufacturerId));
                    Assert.IsFalse(string.IsNullOrEmpty(tokens[i].Model));
                    Assert.IsFalse(string.IsNullOrEmpty(tokens[i].SerialNumber));
                    Assert.IsFalse(tokens[i].Label == null);
                }

                if (!tokenFound)
                    throw new Exception("Required token not found");
            }
        }

        /// <summary>
        /// Tests GetTokenObjects method of Pkcs11Explorer class
        /// </summary>
        [Test()]
        public void GetTokenObjects()
        {
            using (Pkcs11Explorer pkcs11Explorer = new Pkcs11Explorer(_libraryPath))
            {
                List<Token> tokens = pkcs11Explorer.GetTokens();
                Assert.IsTrue(tokens != null && tokens.Count > 0);

                AsymmetricKeyParameter pubKey = null;
                bool keyFound = false;
                bool certFound = false;

                foreach (Token token in tokens)
                {
                    List<PrivateKey> privateKeys = null;
                    List<Certificate> certificates = null;

                    pkcs11Explorer.GetTokenObjects(token, true, _pin, out privateKeys, out certificates);

                    Assert.IsTrue(privateKeys != null && privateKeys.Count > 0);
                    foreach (PrivateKey privateKey in privateKeys)
                    {
                        if ((privateKey.Id == _ckaId) && (privateKey.Label == _ckaLabel))
                        {
                            pubKey = privateKey.PublicKey;
                            keyFound = true;
                        }

                        Assert.IsFalse(string.IsNullOrEmpty(privateKey.Id));
                        Assert.IsFalse(string.IsNullOrEmpty(privateKey.Label));
                    }

                    Assert.IsTrue(certificates != null && certificates.Count > 0);
                    foreach (Certificate certificate in certificates)
                    {
                        if ((keyFound == true) && (certificate.PublicKey != null) && (certificate.PublicKey.Equals(pubKey)))
                            certFound = true;

                        Assert.IsFalse(string.IsNullOrEmpty(certificate.Id));
                        Assert.IsFalse(string.IsNullOrEmpty(certificate.Label));
                        Assert.IsTrue(certificate.Data != null && certificate.Data.Length > 0);
                    }
                }

                if (!keyFound)
                    throw new Exception("Required private key not found");

                if (!certFound)
                    throw new Exception("Required certificate not found");
            }
        }
    }
}
