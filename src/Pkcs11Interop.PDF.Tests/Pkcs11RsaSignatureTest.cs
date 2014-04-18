/*
 *  Pkcs11Interop.PDF - Integration layer for Pkcs11Interop 
 *                      and iText (iTextSharp) libraries
 *  Copyright (c) 2013-2014 JWC s.r.o. <http://www.jwc.sk>
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
using System.IO;
using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using NUnit.Framework;
using Org.BouncyCastle.X509;

namespace Net.Pkcs11Interop.PDF.Tests
{
    /// <summary>
    /// Unit tests that verify Pkcs11RsaSignature implementation
    /// </summary>
    [TestFixture()]
    public class Pkcs11RsaSignatureTest
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
        public const string _ckaId = @"EC5E50A889B888D600C6E13CB0FDF0C1";

        /// <summary>
        /// Hash algorihtm used for the signature creation
        /// </summary>
        public const HashAlgorithm _hashAlgorithm = HashAlgorithm.SHA256;

        /// <summary>
        /// Incorrect string
        /// </summary>
        public const string _incorrectString = @"aabbccddeeff";

        /// <summary>
        /// Signing certificate present on the token
        /// </summary>
        public const string _certificate = @"MIIDOzCCAiOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBCMQswCQYDVQQGEwJTSzEgMB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxETAPBgNVBAMTCEpvaG4gRG9lMB4XDTEzMDUxODAwMDAwMFoXDTIzMDUxNzIzNTk1OVowQjELMAkGA1UEBhMCU0sxIDAeBgNVBAoTF1BrY3MxMUludGVyb3AuUERGLlRlc3RzMREwDwYDVQQDEwhKb2huIERvZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANhZegZNMKv1XKQTaif5o33leIDBiCgFNhqP0eDFlvGeLrESnh3GArbx+zMNSfPsfnqIfrcLvKTGR32HrLogKGCXaVBGN0nIV/o3iHNApROGOY+ekWQAOMfAvUDngYTGx340kwjPyRWmbCjxFY5jxRL3Npv9Dg8y4LBshGARY7JKqrSmpY1WPr9vEQcIox9HS/u9D51ZjB4kuvL5tnQh6pQeiOv94mAMK6+7nwSJFPUopqhb13qHfZytWepEJ6bfbOZZ4kwU9YSyH9R5V48UyfJhc0lFK5CNSbSCyl87qvUnhbSszPTEsL94dyy7bDVf8f1nMkyol63mAOQVGbC5pysCAwEAAaM8MDowDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUaMyotFLpVmy/5ldpUq7mwivA3pQwCwYDVR0PBAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IBAQBfhTjRrwqS0ShZWV17QAggM2PxHf/UCtdO8hBScWzh0CZy0uSElGz23q532kmaO1iZyng976RRX15TU6br1nAoI7OCvvfliVfxl5/ahW5U9VOKgVz2OKp6a6rRcpIiDRrDgohY+ffKOnCAdPyDYw0QYoNYXNarEdPTDrTyjP57HgHMTYBS26HyRDLt1jMxDkUBihMZ8/QmbYNF9MS3Xq9TCyHUaHnEr4tw10whNkSnFrhShhOCQmMBX991LPRejkMyYLfYQz12+7KAOQZEcda6mfNe/H96hXIjfmUNYQ7QAIOMmiES9tKBqUElkZE7LNyVClzZVJyPdAWoJa6lyu+Y";

        /// <summary>
        /// Path to the temporary directory used by these tests
        /// </summary>
        public const string _tempDir = @"c:\temp\";

        #endregion

        #region Constructor tests

        /// <summary>
        /// Tests libraryPath parameter of constructor
        /// </summary>
        [Test()]
        public void ConstructorLibraryPathTest()
        {
            // Existing PKCS#11 library
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, _hashAlgorithm))
                Assert.IsTrue(pkcs11RsaSignature != null);

            // Non-existing PKCS#11 library
            try
            {
                Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_incorrectString, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, _hashAlgorithm);
                pkcs11RsaSignature.Dispose();
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                if (Platform.IsWindows)
                    Assert.IsTrue(ex is Win32Exception);
            }

            // Unspecified PKCS#11 library
            try
            {
                Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(null, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, _hashAlgorithm);
                pkcs11RsaSignature.Dispose();
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentNullException);
            }
        }

        /// <summary>
        /// Tests tokenSerial and tokenLabel parameters of constructor
        /// </summary>
        [Test()]
        public void ConstructorTokenSerialAndLabelTest()
        {
            // Both tokenSerial and tokenLabel specified
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, _hashAlgorithm))
                Assert.IsTrue(pkcs11RsaSignature != null);

            // Only tokenSerial specified
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, null, _pin, _ckaLabel, _ckaId, _hashAlgorithm))
                Assert.IsTrue(pkcs11RsaSignature != null);

            // Only tokenLabel specified
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, null, _tokenLabel, _pin, _ckaLabel, _ckaId, _hashAlgorithm))
                Assert.IsTrue(pkcs11RsaSignature != null);

            // Both tokenSerial and tokenLabel unspecified
            try
            {
                Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, null, null, _pin, _ckaLabel, _ckaId, _hashAlgorithm);
                pkcs11RsaSignature.Dispose();
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentException);
            }

            // Both tokenSerial and tokenLabel incorrect
            try
            {
                Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _incorrectString, _incorrectString, _pin, _ckaLabel, _ckaId, _hashAlgorithm);
                pkcs11RsaSignature.Dispose();
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is TokenNotFoundException);
            }

            // Only tokenSerial incorrect
            try
            {
                Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _incorrectString, _tokenLabel, _pin, _ckaLabel, _ckaId, _hashAlgorithm);
                pkcs11RsaSignature.Dispose();
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is TokenNotFoundException);
            }

            // Only tokenLabel incorrect
            try
            {
                Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _incorrectString, _pin, _ckaLabel, _ckaId, _hashAlgorithm);
                pkcs11RsaSignature.Dispose();
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is TokenNotFoundException);
            }
        }

        /// <summary>
        /// Tests pin parameter of constructor
        /// </summary>
        [Test()]
        public void ConstructorPinTest()
        {
            // Correct PIN
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, _hashAlgorithm))
                Assert.IsTrue(pkcs11RsaSignature != null);

            // Incorrect PIN
            try
            {
                Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _incorrectString, _ckaLabel, _ckaId, _hashAlgorithm);
                pkcs11RsaSignature.Dispose();
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11Exception);
                Assert.IsTrue(((Pkcs11Exception)ex).RV == CKR.CKR_PIN_INCORRECT);
            }
        }

        /// <summary>
        /// Tests ckaLabel and ckaId parameters of constructor
        /// </summary>
        [Test()]
        public void ConstructorCkaLabelAndIdTest()
        {
            // Both ckaLabel and ckaId specified
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, _hashAlgorithm))
                Assert.IsTrue(pkcs11RsaSignature != null);

            // Only ckaLabel specified
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, null, _hashAlgorithm))
                Assert.IsTrue(pkcs11RsaSignature != null);

            // Only ckaId specified
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, null, _ckaId, _hashAlgorithm))
                Assert.IsTrue(pkcs11RsaSignature != null);

            // Both ckaLabel and ckaId unspecified
            try
            {
                Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, null, null, _hashAlgorithm);
                pkcs11RsaSignature.Dispose();
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentException);
            }

            // Both ckaLabel and ckaId incorrect
            try
            {
                Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _incorrectString, _incorrectString, _hashAlgorithm);
                pkcs11RsaSignature.Dispose();
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ObjectNotFoundException);
            }

            // Only ckaLabel incorrect
            try
            {
                Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _incorrectString, _ckaId, _hashAlgorithm);
                pkcs11RsaSignature.Dispose();
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ObjectNotFoundException);
            }

            // Only ckaId incorrect
            try
            {
                Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _incorrectString, _hashAlgorithm);
                pkcs11RsaSignature.Dispose();
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ObjectNotFoundException);
            }
        }

        /// <summary>
        /// Tests hashAlgorithm parameter of constructor
        /// </summary>
        [Test()]
        public void ConstructorHashAlgorihtmTest()
        {
            // Defined hashAlgorihtm
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, _hashAlgorithm))
                Assert.IsTrue(pkcs11RsaSignature != null);

            // Undefined hashAlgorihtm
            try
            {
                Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, (HashAlgorithm)123456);
                pkcs11RsaSignature.Dispose();
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentException);
            }
        }

        #endregion

        #region Raw signature creation tests

        /// <summary>
        /// Tests SHA1withRSA signature creation
        /// </summary>
        [Test()]
        public void SignWithSHA1Test()
        {
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, HashAlgorithm.SHA1))
            {
                byte[] signature = pkcs11RsaSignature.Sign(ConvertUtils.Utf8StringToBytes("Hello world"));
                Assert.IsTrue(pkcs11RsaSignature.GetEncryptionAlgorithm() == "RSA");
                Assert.IsTrue(pkcs11RsaSignature.GetHashAlgorithm() == "SHA1");
                Assert.IsTrue(ConvertUtils.BytesToBase64String(signature) == @"pJ2lelg6SscFTbweImgT25KSblMQa1GgyJZSXwWU+M6vt/n8oApLRHNrw5pvGRZU9iOWi1BXp61VBVLYHS5ABhsBsdRw2/GzEkM0seDje4Q+sx9VKwDIgg6rbkgk+r/tYXjr+95d0kI+GRlELxR6FiQa61OGuSupIRm4Nv58iYN/WNwfvoBjHFNouQPnRC5/79/tehv9uMl2lGkvIl25R7ESjvzDI69b62VwDVFhy+/Jwaru8XDPqpOruFvHtgCFtzhb5yUxG/Lxi3I0Fii9ld1YsrOLLCqPCumjLYmfmSD/nnVMMnxjbzoUadA0uIc8HGXQRkZ+zFZZb8WukXbbMQ==");
            }
        }

        /// <summary>
        /// Tests SHA256withRSA signature creation
        /// </summary>
        [Test()]
        public void SignWithSHA256Test()
        {
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, HashAlgorithm.SHA256))
            {
                byte[] signature = pkcs11RsaSignature.Sign(ConvertUtils.Utf8StringToBytes("Hello world"));
                Assert.IsTrue(pkcs11RsaSignature.GetEncryptionAlgorithm() == "RSA");
                Assert.IsTrue(pkcs11RsaSignature.GetHashAlgorithm() == "SHA256");
                Assert.IsTrue(ConvertUtils.BytesToBase64String(signature) == @"rp2lDiHzzru8dUTs6Gr0JpaJ1XdHTcSLHjourbDcV84vSGjNtaO3T+fBlq0zoTihnjpoGnZxHDVXTRLSCrWv+EEPrUVLF1UdMeJ6k50i7YZCK3S+caUEdQlH1kWzsMrvm40TTuyQ7a0nRImBB44wpKDir2bjvNaR45ZkTDbfqUZFjfhVena2+EattXANcyoxOiq9P1OjMVbVE4kyNmaJQ3p67E60UrrLnHZbZcMakhmewc3lGFGs0BpORJ7iwSGMH+8sT1ZhRoBi1Ra0gzumCFlSFcB/b85orDitGJHbyNDJu+FzbuzUgFgxM8u4f102hp6h/w7xwZMB2wkrLb5wbA==");
            }
        }

        /// <summary>
        /// Tests SHA384withRSA signature creation
        /// </summary>
        [Test()]
        public void SignWithSHA384Test()
        {
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, HashAlgorithm.SHA384))
            {
                byte[] signature = pkcs11RsaSignature.Sign(ConvertUtils.Utf8StringToBytes("Hello world"));
                Assert.IsTrue(pkcs11RsaSignature.GetEncryptionAlgorithm() == "RSA");
                Assert.IsTrue(pkcs11RsaSignature.GetHashAlgorithm() == "SHA384");
                Assert.IsTrue(ConvertUtils.BytesToBase64String(signature) == @"cyO/5SArMSV8zs4u747/+OEgOociqSqs0OU05OdVWAQI4e+YQxiNfDMJaeIGsFbcnhuOvJeBOo8TFgvNhncPz9LwFuNw6fWaCuXdtLB+Ewh2H/xhURGAZxbmXYHKs8TRwEDAGbuY9rkglBzuijLxSsc202Cf0Ym8jnAKkgwpcTFYgDnNcm857ZNxQ35UinqqxjvZOEpBdej3+9jwyDFsTQ6en5z/S7tDwnGe6C7uuIU6sXKn4ydTjp/HndVRiTQwTHMgKJF4V3K1yOYX/aFocIchd2ergLE5WrRJT8PwfDRupoHzSd8LREFmN8Z+nqv17Adfpm6rcVDG0ZluismlIA==");
            }
        }

        /// <summary>
        /// Tests SHA512withRSA signature creation
        /// </summary>
        [Test()]
        public void SignWithSHA512Test()
        {
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, HashAlgorithm.SHA512))
            {
                byte[] signature = pkcs11RsaSignature.Sign(ConvertUtils.Utf8StringToBytes("Hello world"));
                Assert.IsTrue(pkcs11RsaSignature.GetEncryptionAlgorithm() == "RSA");
                Assert.IsTrue(pkcs11RsaSignature.GetHashAlgorithm() == "SHA512");
                Assert.IsTrue(ConvertUtils.BytesToBase64String(signature) == @"i/0If7M+T2eEbO/VNoV37ikIMDbs88//svdcsC3qfCc1cvjcbXrcojwY07rQaQfbpguQAbUi2OtNHLRgjaPhag3Zo4PczNVtmhHxWLeo0LTqpDd9+6N75HNIvV18RD1f1ms5Dw2LKWxz6KiZCJGWH7yB7qgbYx1YJeqhaGtFgxOdjbPn/R32ch0PDYAY9oAAkVejGW9xaVl1hspNRBOkhQag4MumI0icmKoDkqpLXzUg1XleTTY563xGm3Q+f6YrwQ+W1HeYRpp2LdEG6azStTi/FM8Mr5TAh2Xmm4v9EavKe6xzd+avuP2KViwRFrRHMYu6Xn1kVOIG7knAa1ZsAg==");
            }
        }

        #endregion

        #region GetCertificate tests

        /// <summary>
        /// Finds slot containing the token that matches specified criteria
        /// </summary>
        /// <param name="pkcs11">High level PKCS#11 wrapper</param>
        /// <param name="tokenSerial">Serial number of token that should be found</param>
        /// <param name="tokenLabel">Label of token that should be found</param>
        /// <returns>Slot containing the token that matches specified criteria</returns>
        private Slot FindSlot(Pkcs11 pkcs11, string tokenSerial, string tokenLabel)
        {
            if (pkcs11 == null)
                throw new ArgumentNullException("pkcs11");

            if (string.IsNullOrEmpty(tokenSerial) && string.IsNullOrEmpty(tokenLabel))
                throw new ArgumentException("Token serial and/or label has to be specified");

            List<Slot> slots = pkcs11.GetSlotList(true);
            foreach (Slot slot in slots)
            {
                TokenInfo tokenInfo = slot.GetTokenInfo();

                if (!string.IsNullOrEmpty(tokenSerial))
                    if (0 != String.Compare(tokenSerial, tokenInfo.SerialNumber, StringComparison.InvariantCultureIgnoreCase))
                        continue;

                if (!string.IsNullOrEmpty(tokenLabel))
                    if (0 != String.Compare(tokenLabel, tokenInfo.Label, StringComparison.InvariantCultureIgnoreCase))
                        continue;

                return slot;
            }

            return null;
        }

        /// <summary>
        /// Tests GetSigningCertificate method
        /// </summary>
        [Test()]
        public void GetSigningCertificateTest()
        {
            // CKA_ID and CKA_LABEL of the temporary RSA key pair
            byte[] ckaId = null;
            string ckaLabel = null;

            // Generate temporary RSA key pair
            using (Pkcs11 pkcs11 = new Pkcs11(_libraryPath, false))
            {
                Slot slot = FindSlot(pkcs11, _tokenSerial, _tokenLabel);
                if (slot == null)
                    throw new TokenNotFoundException();

                using (Session session = slot.OpenSession(false))
                {
                    session.Login(CKU.CKU_USER, _pin);

                    ckaId = session.GenerateRandom(20);
                    ckaLabel = Guid.NewGuid().ToString();

                    List<ObjectAttribute> publicKeyAttributes = new List<ObjectAttribute>();
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, false));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, ckaLabel));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY_RECOVER, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_WRAP, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_MODULUS_BITS, 1024));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 }));

                    List<ObjectAttribute> privateKeyAttributes = new List<ObjectAttribute>();
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, ckaLabel));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SENSITIVE, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_DECRYPT, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN_RECOVER, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_UNWRAP, true));

                    ObjectHandle publicKeyHandle = null;
                    ObjectHandle privateKeyHandle = null;
                    session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);

                    session.Logout();
                }
            }

            // Test Pkcs11RsaSignature with RSA key pair associated with certificate present on the token
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, _hashAlgorithm))
            {
                byte[] cert = pkcs11RsaSignature.GetSigningCertificate();
                Assert.IsTrue(cert != null);
                Assert.IsTrue(ConvertUtils.BytesToBase64String(cert) == _certificate);
            }

            // Test Pkcs11RsaSignature with temporary RSA key pair that is not associated with any certificate present on the token
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, ckaLabel, ConvertUtils.BytesToHexString(ckaId), _hashAlgorithm))
            {
                try
                {
                    pkcs11RsaSignature.GetSigningCertificate();
                    Assert.Fail("Exception expected but not thrown");
                }
                catch (Exception ex)
                {
                    Assert.IsTrue(ex is ObjectNotFoundException);
                }
            }

            // Delete temporary RSA key pair
            using (Pkcs11 pkcs11 = new Pkcs11(_libraryPath, false))
            {
                Slot slot = FindSlot(pkcs11, _tokenSerial, _tokenLabel);
                if (slot == null)
                    throw new TokenNotFoundException();

                using (Session session = slot.OpenSession(false))
                {
                    session.Login(CKU.CKU_USER, _pin);

                    List<ObjectAttribute> objectAttributes = new List<ObjectAttribute>();
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, ckaLabel));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));

                    List<ObjectHandle> foundObjects = session.FindAllObjects(objectAttributes);
                    foreach (ObjectHandle foundObject in foundObjects)
                        session.DestroyObject(foundObject);

                    session.Logout();
                }
            }
        }

        /// <summary>
        /// Tests GetAllCertificates method
        /// </summary>
        [Test()]
        public void GetAllCertificatesTest()
        {
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, _hashAlgorithm))
            {
                List<byte[]> allCerts = pkcs11RsaSignature.GetAllCertificates();
                Assert.IsTrue(allCerts != null && allCerts.Count > 0);

                bool signingCertFound = false;
                foreach (byte[] cert in allCerts)
                {
                    if (ConvertUtils.BytesToBase64String(cert) == _certificate)
                    {
                        signingCertFound = true;
                        return;
                    }
                }

                if (!signingCertFound)
                    Assert.Fail("Signing certificate is not present in the list of all certificates");
            }
        }

        #endregion

        #region PDF signature creation tests

        /// <summary>
        /// Generates unique path to the temporary PDF file
        /// </summary>
        /// <returns>Path to the temporary PDF file</returns>
        private static string GetTempDocPath()
        {
            return Path.Combine(_tempDir, Guid.NewGuid().ToString() + ".pdf");
        }

        /// <summary>
        /// Generates PDF document with random content
        /// </summary>
        /// <param name="path">Path to the PDF document that should be created</param>
        /// <param name="paragraphCount">Number of paragraphs to add (defaults to 1)</param>
        private static void GenerateRandomPdf(string path, int paragraphCount = 1)
        {
            using (Document document = new Document(PageSize.A4, 50, 50, 50, 50))
            {
                using (FileStream outputStream = new FileStream(path, FileMode.Create))
                {
                    using (PdfWriter pdfWriter = PdfWriter.GetInstance(document, outputStream))
                    {
                        document.Open();
                        for (int i = 0; i < paragraphCount; i++)
                            document.Add(new Paragraph(Guid.NewGuid().ToString()));
                        document.Close();
                    }
                }
            }
        }

        /// <summary>
        /// Verifies integrity of all PDF signatures
        /// </summary>
        /// <param name="path">Path to the PDF document that should be verified</param>
        /// <returns>Number of PDF signatures verified</returns>
        private static int VerifySignatureIntegrity(string path)
        {
            using (PdfReader reader = new PdfReader(path))
            {
                List<string> signatureNames = reader.AcroFields.GetSignatureNames();
                foreach (string signatureName in signatureNames)
                {
                    PdfPKCS7 pdfPkcs7 = reader.AcroFields.VerifySignature(signatureName);
                    Assert.IsTrue(pdfPkcs7.Verify());
                }

                return signatureNames.Count;
            }
        }

        /// <summary>
        /// Tests creation of single signature
        /// </summary>
        [Test()]
        public void SingleSignatureTest()
        {
            string unsignedPdfPath = GetTempDocPath();
            string signedPdfPath = GetTempDocPath();

            try
            {
                GenerateRandomPdf(unsignedPdfPath);

                using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, _hashAlgorithm))
                {
                    byte[] signingCertificate = pkcs11RsaSignature.GetSigningCertificate();
                    List<byte[]> otherCertificates = pkcs11RsaSignature.GetAllCertificates();
                    ICollection<X509Certificate> certPath = CertUtils.BuildCertPath(signingCertificate, otherCertificates);

                    using (PdfReader pdfReader = new PdfReader(unsignedPdfPath))
                    using (FileStream outputStream = new FileStream(signedPdfPath, FileMode.Create))
                    using (PdfStamper pdfStamper = PdfStamper.CreateSignature(pdfReader, outputStream, '\0', GetTempDocPath(), true))
                        MakeSignature.SignDetached(pdfStamper.SignatureAppearance, pkcs11RsaSignature, certPath, null, null, null, 0, CryptoStandard.CADES);
                }

                Assert.IsTrue(1 == VerifySignatureIntegrity(signedPdfPath));
            }
            finally
            {
                File.Delete(unsignedPdfPath);
                File.Delete(signedPdfPath);
            }
        }

        /// <summary>
        /// Tests creation of three signatures
        /// </summary>
        [Test()]
        public void TripleSignatureTest()
        {
            string unsignedPdfPath = GetTempDocPath();
            string signedPdfPath = GetTempDocPath();

            GenerateRandomPdf(unsignedPdfPath);

            try
            {
                for (int i = 1; i <= 3; i++)
                {
                    if (i != 1)
                    {
                        File.Delete(unsignedPdfPath);
                        unsignedPdfPath = signedPdfPath;
                        signedPdfPath = GetTempDocPath();
                    }

                    using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, _hashAlgorithm))
                    {
                        byte[] signingCertificate = pkcs11RsaSignature.GetSigningCertificate();
                        List<byte[]> otherCertificates = pkcs11RsaSignature.GetAllCertificates();
                        ICollection<X509Certificate> certPath = CertUtils.BuildCertPath(signingCertificate, otherCertificates);

                        using (PdfReader pdfReader = new PdfReader(unsignedPdfPath))
                        using (FileStream outputStream = new FileStream(signedPdfPath, FileMode.Create))
                        using (PdfStamper pdfStamper = PdfStamper.CreateSignature(pdfReader, outputStream, '\0', GetTempDocPath(), true))
                            MakeSignature.SignDetached(pdfStamper.SignatureAppearance, pkcs11RsaSignature, certPath, null, null, null, 0, CryptoStandard.CADES);
                    }

                    Assert.IsTrue(i == VerifySignatureIntegrity(signedPdfPath));
                }
            }
            finally
            {
                File.Delete(unsignedPdfPath);
                File.Delete(signedPdfPath);
            }
        }

        /// <summary>
        /// Tests huge file singing
        /// </summary>
        [Test()]
        public void SingleSignatureHugeFileTest()
        {
            string unsignedPdfPath = GetTempDocPath();
            string signedPdfPath = GetTempDocPath();

            try
            {
                // Generate PDF with cca. 25000 pages and 30MB in size
                GenerateRandomPdf(unsignedPdfPath, 1000000);

                using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, _hashAlgorithm))
                {
                    byte[] signingCertificate = pkcs11RsaSignature.GetSigningCertificate();
                    List<byte[]> otherCertificates = pkcs11RsaSignature.GetAllCertificates();
                    ICollection<X509Certificate> certPath = CertUtils.BuildCertPath(signingCertificate, otherCertificates);

                    using (PdfReader pdfReader = new PdfReader(unsignedPdfPath))
                    using (FileStream outputStream = new FileStream(signedPdfPath, FileMode.Create))
                    using (PdfStamper pdfStamper = PdfStamper.CreateSignature(pdfReader, outputStream, '\0', GetTempDocPath(), true))
                        MakeSignature.SignDetached(pdfStamper.SignatureAppearance, pkcs11RsaSignature, certPath, null, null, null, 0, CryptoStandard.CADES);
                }

                Assert.IsTrue(1 == VerifySignatureIntegrity(signedPdfPath));
            }
            finally
            {
                File.Delete(unsignedPdfPath);
                File.Delete(signedPdfPath);
            }
        }

        /// <summary>
        /// Tests signing of 100 independent PDF documents with a single instance of Pkcs11RsaSignature class
        /// </summary>
        [Test()]
        public void Pkcs11RsaSignatureReuseTest()
        {
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(_libraryPath, _tokenSerial, _tokenLabel, _pin, _ckaLabel, _ckaId, _hashAlgorithm))
            {
                byte[] signingCertificate = pkcs11RsaSignature.GetSigningCertificate();
                List<byte[]> otherCertificates = pkcs11RsaSignature.GetAllCertificates();
                ICollection<X509Certificate> certPath = CertUtils.BuildCertPath(signingCertificate, otherCertificates);

                for (int i = 0; i < 100; i++)
                {
                    string unsignedPdfPath = GetTempDocPath();
                    string signedPdfPath = GetTempDocPath();

                    try
                    {
                        GenerateRandomPdf(unsignedPdfPath);

                        using (PdfReader pdfReader = new PdfReader(unsignedPdfPath))
                        using (FileStream outputStream = new FileStream(signedPdfPath, FileMode.Create))
                        using (PdfStamper pdfStamper = PdfStamper.CreateSignature(pdfReader, outputStream, '\0', GetTempDocPath(), true))
                            MakeSignature.SignDetached(pdfStamper.SignatureAppearance, pkcs11RsaSignature, certPath, null, null, null, 0, CryptoStandard.CADES);

                        Assert.IsTrue(1 == VerifySignatureIntegrity(signedPdfPath));
                    }
                    finally
                    {
                        File.Delete(unsignedPdfPath);
                        File.Delete(signedPdfPath);
                    }
                }
            }
        }

        #endregion
    }
}
