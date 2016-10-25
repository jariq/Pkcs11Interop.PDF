/*
 *  Pkcs11Interop.PDF - Integration layer for Pkcs11Interop 
 *                      and iText (iTextSharp) libraries
 *  Copyright (c) 2013-2016 JWC s.r.o. <http://www.jwc.sk>
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
        public const string _ckaId = @"73006233654C4C88A21555CC882AFA58";

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
        public const string _certificate = @"MIIDPTCCAiWgAwIBAgIBATANBgkqhkiG9w0BAQsFADBCMQswCQYDVQQGEwJTSzEgMB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxETAPBgNVBAMTCEpvaG4gRG9lMCAXDTE2MDEwMTAwMDAwMFoYDzIxMTUxMjMxMjM1OTU5WjBCMQswCQYDVQQGEwJTSzEgMB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxETAPBgNVBAMTCEpvaG4gRG9lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzDP73KjmePdxPuDCWzZDeelfY1UZfFRxTqHkf3VGNY4ah3T+p6PResyh72O+MgItwCKec3nCctuw836a+iojqvdePbbZXRSLx31+vlBRwHPfzGiRMQmuQQm9+1xv3Il1CKd2FAA4dAlfFLubaBopdYTSOKDmvvdFGRax74lFDHUE6g7NaP2n644notb5aHj/5lOYx/VUicSJahVVVpHaQN7hKwTCnAmx9yr32j0rwxlvbzxGgaWATadJaRmbGNW52p+iWhNgOUxJlC3LHJZNBvzi8BIW/i0RYp6u+8HXUDgw+djuqcroA2vGi4Ns/F26elc87nFepdJA4QnsnQyTlwIDAQABozwwOjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTKh4hjBUe7fVeIbiBvKwT+0vMOTjALBgNVHQ8EBAMCBLAwDQYJKoZIhvcNAQELBQADggEBAKriwcNMJ40NxTfyOlCJ/YbTFur0EWLQnS1sSkpDkbm5Egm+HuCZrX3aTl+AoGOAHFTwetHJZc7CxwlBT12sKV8P6jUXrqnpNOI6u6BMAvDL9LO5BQN4IEDKKm+UIaKxltVjIB0yiK1e8g5MgXXAGnDLgr1BoDf7U06/FQ+TX1Kru/+LR+vnJcaUSzYppK3LPdBEcoXoeTHEXa6WDZPn7qa2BsLFiXGin3HEBchiD/gC2Ydv/DNgVAXnSSmQYZUI9nuiiHiUu5SWW0+9Mu8UD7MSpIxFl5QNHY5l0NdO8w1p5bzcHZIAso9nS+7Jdlv/rxe7lfHfl7cm7/HWROkzR9Q=";

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
                Assert.IsTrue(ex is UnmanagedException);
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
                Assert.IsTrue(ConvertUtils.BytesToBase64String(signature) == @"ANaql6sPuTp25Is2V6boFuTwIrBJ7eiM+z4OxcfHIHWiQ1SnBGfpFFdXfnpklTdwYenRpFxaHW6KlNYEIRk9Jkc0ZAJI83QYMmB99mdbnFLxVWqfpO9+41nOv08oe1RZxLp69pWUF0W1yFPwWmB/azH1x3wLkQlLTmxfCo7IEA7v+wlWZn5OosLVL2RjHMAKEcLBbcz9GuEC+BFAiFGRQCVZhWH0k5BgL38cG+Y0PMo+NH2LQy9Hh0neC+3VsQpQgHJM7n5H0/ck1Oay5jSv29I+PoiUMCmEg6txjElYvsrGEB6GwCuO1o5TwjqlADi+KeKqiH3BsIrTS0NTejLW9Q==");
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
                Assert.IsTrue(ConvertUtils.BytesToBase64String(signature) == @"TL4ZfPMONv5EFO1cI8ni8YuOkPB/0XXjCQPSHH7r3NejQpNCWD0P4OHRIIYYOMYjJwwRbstS+zX5YigR7Wo8j3OrNs5/H3e9k0OcIidM4WFVz7h5frMmaLo+kbVwnA8zGAaYiXAxgQGHH1Qr31pYkVifWx6/Wq+/J4iKVLXFr25mrIwg/Ccfar587HMi3KzPYYNtKIglkqTTTqrzxBv+VW9Ty2TB+YbTJ/3FsBz6+PWHLPCrECizvCKZyT56EOj6QkJ6bZSMt6N42ng187ZgnatwjYJd3HitX146qNpoR5Hp2yjPSBgxxww/U66O2v1SQV1fBz/bGpQ/t6JLODkAmA==");
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
                Assert.IsTrue(ConvertUtils.BytesToBase64String(signature) == @"cuI+JqxscNrX1ZK/PtyTTJmWsRttSivokif2RkbhiAcgXS/6VxDGup83BGMwy+Yttv9miqrPY/dp0GB4TcAbWoYsXhKB+zTs3BlCAvHrDobpvz/wkhLry7AsAjCFUt9ax2ySfAU3PyUkKRkD2WwlDV3DVwAdKZhfkElL8ocYfoAod5u2X8/78HDVod9umUf8Yj1MI0xPdtaOTO1YLWS3Pd9TgXI0IuzbtY/QYO79PVaaalzZYROIy+kwJkkE/N9nQMRg2BVxSEvkd29/Vv98Z/OMDDVFga26BsYhhS9KUw8lKnk7qk7QvSKbPDvhQmTMwNfL++Yi2E4Df8bVk2O1JA==");
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
                Assert.IsTrue(ConvertUtils.BytesToBase64String(signature) == @"nfTYFqxGibgo6Gf5I9AYSVIHyZrCCN1xS8QQkaWVx1JE6pJS0p4urlDTE5RshYBNQ1xxoxTzKpKk5z1TBj0Bzmx0lvhjFpMELW/47xxkYNeBMbfauIIKy2wjvIAlZ1STEGOc622tyPNC9XS9phiJpnmtzOLzetIMwJM+/xCyqLWZmRPilE2luu63w2b60vnfHKSDFeeqtxCd5vvkXsp8iz1A2xLxqEVVrCyQR9qJMAKT5KrApuEHxTLuqqBPO9jV4oFoAu2a+nFlTXk//aU0YfDqsTBeuf2DzhnLAajV3wdCTuKxMlR6jhzXwANLvcq5N8L1Fr7gfj9VX/tuRfNgEw==");
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
