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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NUnit.Framework;
using BCX509 = Org.BouncyCastle.X509;

namespace Net.Pkcs11Interop.PDF.Tests
{
    /// <summary>
    /// Unit tests for CertUtils class
    /// </summary>
    [TestFixture()]
    public class CertUtilsTest
    {
        #region Test data

        /// <summary>
        /// DER encoded certificate
        /// </summary>
        byte[] _derCert = Convert.FromBase64String(@"MIIDPTCCAiWgAwIBAgIBATANBgkqhkiG9w0BAQsFADBCMQswCQYDVQQGEwJTSzEgMB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxETAPBgNVBAMTCEpvaG4gRG9lMCAXDTE2MDEwMTAwMDAwMFoYDzIxMTUxMjMxMjM1OTU5WjBCMQswCQYDVQQGEwJTSzEgMB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxETAPBgNVBAMTCEpvaG4gRG9lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzDP73KjmePdxPuDCWzZDeelfY1UZfFRxTqHkf3VGNY4ah3T+p6PResyh72O+MgItwCKec3nCctuw836a+iojqvdePbbZXRSLx31+vlBRwHPfzGiRMQmuQQm9+1xv3Il1CKd2FAA4dAlfFLubaBopdYTSOKDmvvdFGRax74lFDHUE6g7NaP2n644notb5aHj/5lOYx/VUicSJahVVVpHaQN7hKwTCnAmx9yr32j0rwxlvbzxGgaWATadJaRmbGNW52p+iWhNgOUxJlC3LHJZNBvzi8BIW/i0RYp6u+8HXUDgw+djuqcroA2vGi4Ns/F26elc87nFepdJA4QnsnQyTlwIDAQABozwwOjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTKh4hjBUe7fVeIbiBvKwT+0vMOTjALBgNVHQ8EBAMCBLAwDQYJKoZIhvcNAQELBQADggEBAKriwcNMJ40NxTfyOlCJ/YbTFur0EWLQnS1sSkpDkbm5Egm+HuCZrX3aTl+AoGOAHFTwetHJZc7CxwlBT12sKV8P6jUXrqnpNOI6u6BMAvDL9LO5BQN4IEDKKm+UIaKxltVjIB0yiK1e8g5MgXXAGnDLgr1BoDf7U06/FQ+TX1Kru/+LR+vnJcaUSzYppK3LPdBEcoXoeTHEXa6WDZPn7qa2BsLFiXGin3HEBchiD/gC2Ydv/DNgVAXnSSmQYZUI9nuiiHiUu5SWW0+9Mu8UD7MSpIxFl5QNHY5l0NdO8w1p5bzcHZIAso9nS+7Jdlv/rxe7lfHfl7cm7/HWROkzR9Q=");

        /// <summary>
        /// PEM encoded certificate
        /// </summary>
        byte[] _pemCert = ASCIIEncoding.ASCII.GetBytes(@"-----BEGIN CERTIFICATE-----
MIIDPTCCAiWgAwIBAgIBATANBgkqhkiG9w0BAQsFADBCMQswCQYDVQQGEwJTSzEg
MB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxETAPBgNVBAMTCEpvaG4g
RG9lMCAXDTE2MDEwMTAwMDAwMFoYDzIxMTUxMjMxMjM1OTU5WjBCMQswCQYDVQQG
EwJTSzEgMB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxETAPBgNVBAMT
CEpvaG4gRG9lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzDP73Kjm
ePdxPuDCWzZDeelfY1UZfFRxTqHkf3VGNY4ah3T+p6PResyh72O+MgItwCKec3nC
ctuw836a+iojqvdePbbZXRSLx31+vlBRwHPfzGiRMQmuQQm9+1xv3Il1CKd2FAA4
dAlfFLubaBopdYTSOKDmvvdFGRax74lFDHUE6g7NaP2n644notb5aHj/5lOYx/VU
icSJahVVVpHaQN7hKwTCnAmx9yr32j0rwxlvbzxGgaWATadJaRmbGNW52p+iWhNg
OUxJlC3LHJZNBvzi8BIW/i0RYp6u+8HXUDgw+djuqcroA2vGi4Ns/F26elc87nFe
pdJA4QnsnQyTlwIDAQABozwwOjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTKh4hj
BUe7fVeIbiBvKwT+0vMOTjALBgNVHQ8EBAMCBLAwDQYJKoZIhvcNAQELBQADggEB
AKriwcNMJ40NxTfyOlCJ/YbTFur0EWLQnS1sSkpDkbm5Egm+HuCZrX3aTl+AoGOA
HFTwetHJZc7CxwlBT12sKV8P6jUXrqnpNOI6u6BMAvDL9LO5BQN4IEDKKm+UIaKx
ltVjIB0yiK1e8g5MgXXAGnDLgr1BoDf7U06/FQ+TX1Kru/+LR+vnJcaUSzYppK3L
PdBEcoXoeTHEXa6WDZPn7qa2BsLFiXGin3HEBchiD/gC2Ydv/DNgVAXnSSmQYZUI
9nuiiHiUu5SWW0+9Mu8UD7MSpIxFl5QNHY5l0NdO8w1p5bzcHZIAso9nS+7Jdlv/
rxe7lfHfl7cm7/HWROkzR9Q=
-----END CERTIFICATE-----");

        /// <summary>
        /// Arbitrary byte array 
        /// </summary>
        byte[] _noCert = ASCIIEncoding.ASCII.GetBytes(@"Hello world");

        /// <summary>
        /// Certificate of random self-signed Root CA
        /// </summary>
        byte[] _rootCA = Convert.FromBase64String(@"MIIDPjCCAiagAwIBAgIBATANBgkqhkiG9w0BAQsFADBBMQswCQYDVQQGEwJTSzEgMB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxEDAOBgNVBAMTB1Jvb3QgQ0EwIBcNMTYwMTAxMDAwMDAwWhgPMjExNTEyMzEyMzU5NTlaMEExCzAJBgNVBAYTAlNLMSAwHgYDVQQKExdQa2NzMTFJbnRlcm9wLlBERi5UZXN0czEQMA4GA1UEAxMHUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALPrW4QtTisxdzuj2NozBQcUuwpliRbQNmvZpwVeDnT655JRXma3Sj5tctmvxPSNSXXfO5zvDyXC0V+dyDdr34Do2ghHT8YewH3LNrQ3Z/iS5gCphqrMzbOhpzFt0n3C3jmFVs5+NWTVLwY9s543PPL8yXJ2BUcWHAVPaROFyFr+5pL+0Bygv1s6Ao5sflxVwGdBUHRN0kn912iVvpafJQkdXa6kPdCYOuIGy1UJffrL6MbJyPBVwLEcMDH5Ra97siarbygfjExoMLVDhmetvbnfXZvx3VR+6IPeWY5k/fEoC7/FxJtVLZeWUPb77400DohAUAbwDPxV5i5iPuBrJ4UCAwEAAaM/MD0wDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUt8II8QN2Eh56Rl0riqkzJIoSjw8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQAYSKQRwHLRWKLKClR4il72AI9H7a95LZYbCRTEcgvPqepM7sTd7tdiFZ1z71c1ofQ5IY7dK6LhdLL8alBdkm0hnIcrqsCfJ/vX5Q5D1jkJ4obdSSDZwzLRM1pvtEtaJSrWxyz5RT/AMkDfwyz0wYxvo9xk44JxLgGywNa3sVie/3SvW18M8bSp2I4xJsRU5MTm2EG+uOOOrZgO5gJui9dHLknVbHzHkx0lUq8Z53BKFt4FqeYSdzwpKAgNmMYOPNad4iC48fqTU0XO4pdf+AuYDvEIxHpJjOYQ+YaprTxLB2aiAVJ0JACoj3vU/tJDBx+XUWopVr0B1opoK+o6JXem");

        /// <summary>
        /// Certificate of random Intermediate CA signed by Root CA
        /// </summary>
        byte[] _subCA = Convert.FromBase64String(@"MIIDRjCCAi6gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBBMQswCQYDVQQGEwJTSzEgMB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxEDAOBgNVBAMTB1Jvb3QgQ0EwIBcNMTYwMTAxMDAwMDAwWhgPMjExNTEyMzEyMzU5NTlaMEkxCzAJBgNVBAYTAlNLMSAwHgYDVQQKExdQa2NzMTFJbnRlcm9wLlBERi5UZXN0czEYMBYGA1UEAxMPSW50ZXJtZWRpYXRlIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1G1oNno0mRnmD2NgDy0iVQzWWqz3hH6lIgUvMo9bPOnwsL/Zd79Rn1ZAc4acmS5zwMgVBd4iDTjdzMYfzhwVkuymsvKixWeFcWifHByuqh2OREqz//LF7lDZRD0KNxmyYfrq1Tv2izhrUzrTwAVJVv9HO4cKo4nFfJ9QlVto16FuduN++ycTVedNJkMV5HzeAkw7lIOgshOmw7nnVuJHfNjyKeqCgjD/sGFzEM/oyIhP0NBAfu66SYQInPmL+BUfMiHEGMCf+W6GUZhXbXJpFbTyh3cXs98Q9GHToK3+/XnUK+TSxDhBSz6U0gnhq5tm+UNPEWSSmm2a/aj+xq8+BwIDAQABoz8wPTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQX5b1TA7X5wBIGvwm4l9QF7Z0FHzALBgNVHQ8EBAMCAQYwDQYJKoZIhvcNAQELBQADggEBAEP2iWQ5l49WWqpY7QPGayPgRjHhATqQd0/URsPpwS26r9PEc/4YxT2G1b/DSdbhR1yhiOIY0rXGKWhpZK5sjWz2cIg4IRNBzok9XqxcWKZ2rC7zMvmb5MVQmIjIpGvoyO4nWGj1gdZ0xQ+9PVSd0o9b05GOy8RhSvQof5n/i2sm+FonBHJZIumymvsN9bwrEUMt/DFo0SkZies98iot2H+KpLAb3WEP4zm3YIA2JPZd/qIrleocDZYhm+cOaFlxQf7TSU4r2gHqTfvY24K4lxbTu7KAO8QVdwUPj3cO7Z24sAmMCqMd0CvT9dFlzcU2e87kORGHNSNO9YueH2BpPgg=");

        /// <summary>
        /// Certificate of random End Entity signed by Intermediate CA
        /// </summary>
        byte[] _endEntity = Convert.FromBase64String(@"MIIDRjCCAi6gAwIBAgIBAzANBgkqhkiG9w0BAQsFADBJMQswCQYDVQQGEwJTSzEgMB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxGDAWBgNVBAMTD0ludGVybWVkaWF0ZSBDQTAgFw0xNjAxMDEwMDAwMDBaGA8yMTE1MTIzMTIzNTk1OVowRDELMAkGA1UEBhMCU0sxIDAeBgNVBAoTF1BrY3MxMUludGVyb3AuUERGLlRlc3RzMRMwEQYDVQQDEwpFbmQgRW50aXR5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2zKQFsuu5SnuNDVcvwshQJBZcZ0ne7k6vA+bEl3mClbdDP6qy5AvLKdK1ycac6JEIMi71pHhts1R+qrPtzO4yvCJdp9tbXSgWIcpKpQq5or0oZFQ9MPqapb4AvKk9GrY7CI85aGwlTHc6/KX2kliOGP6ojZWJXFntouG7MUO+HLcWxEFD4U8yId+1c0dpwVCy/t2JNnKrQAMDMCd/lmRSJ8YxdlmG80TCPT09JdWg/Yo5GvkTb4+KMIywoEqdBwgIm3oyCRZ8yx2pxxPzjY5jNFYTJVKXMf0JFoR4E5/sy25LM3OcJThac0MUtqULS7gOM2UKxXYQw0P55u6ZVL+twIDAQABozwwOjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSG3SMb/1sAiGcadEdLXu3FGPIW5jALBgNVHQ8EBAMCBLAwDQYJKoZIhvcNAQELBQADggEBAH1OAbPSjvEZ3da9YJV79UgDEbDV3f/tMQrF+Vyl8IZqqxW/koD2k1+j92K3/EK74ars/WmghR7NQvAOVfYEop7y7aTFXw2lSfLGxpCflD45cPq1iMQBBNfWTMc1U1erd4ALikkmHq9fQ8PED3Io2AHUE5+7DL7FPqMio3mGg68wDiMSzaBeUfbUboCT8Ey/o22IPpVTd1MhAEPH3Zpotq7E3D5M0R+Y4u2aZvYzE/+PJ7bYVrXzkbTfjZpj33hDi0gXE5N+Z3in8VHilmSM2T6C4uKx2TX6M0qJPe/TTUVbvsVEizGmDJ2t89koDcu5Ea+N74l6JgG9U8+b+y9PfII=");

        #endregion

        /// <summary>
        /// Tests certificate conversion to .NET X509Certificate2 object
        /// </summary>
        [Test()]
        public void ConvertToDotNetObjectTest()
        {
            X509Certificate2 dotNetCert = null;
            BCX509.X509Certificate bcCert = null;

            // From ByteArray
            try
            {
                dotNetCert = CertUtils.ToDotNetObject((byte[])null);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentNullException);
            }

            dotNetCert = CertUtils.ToDotNetObject(_derCert);
            Assert.IsTrue(dotNetCert != null);

            dotNetCert = CertUtils.ToDotNetObject(_pemCert);
            Assert.IsTrue(dotNetCert != null);

            try
            {
                dotNetCert = CertUtils.ToDotNetObject(_noCert);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is CryptographicException);
            }

            // From BouncyCastleObject
            try
            {
                dotNetCert = CertUtils.ToDotNetObject((BCX509.X509Certificate)null);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentNullException);
            }

            bcCert = CertUtils.ToBouncyCastleObject(_derCert);
            dotNetCert = CertUtils.ToDotNetObject(bcCert);
            Assert.IsTrue(dotNetCert != null);

            CertUtils.ToBouncyCastleObject(_pemCert);
            dotNetCert = CertUtils.ToDotNetObject(bcCert);
            Assert.IsTrue(dotNetCert != null);
        }

        /// <summary>
        /// Tests certificate conversion to BouncyCastle X509Certificate object
        /// </summary>
        [Test()]
        public void ConvertToBouncyCastleObjectTest()
        {
            X509Certificate2 dotNetCert = null;
            BCX509.X509Certificate bcCert = null;

            // From ByteArray
            try
            {
                bcCert = CertUtils.ToBouncyCastleObject((byte[])null);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentNullException);
            }

            bcCert = CertUtils.ToBouncyCastleObject(_derCert);
            Assert.IsTrue(bcCert != null);

            bcCert = CertUtils.ToBouncyCastleObject(_pemCert);
            Assert.IsTrue(bcCert != null);

            try
            {
                bcCert = CertUtils.ToBouncyCastleObject(_noCert);
                Assert.IsTrue(bcCert == null);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is CryptographicException);
            }

            // From DotNetObject
            try
            {
                bcCert = CertUtils.ToBouncyCastleObject((X509Certificate2)null);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentNullException);
            }

            dotNetCert = CertUtils.ToDotNetObject(_derCert);
            bcCert = CertUtils.ToBouncyCastleObject(dotNetCert);
            Assert.IsTrue(bcCert != null);

            dotNetCert = CertUtils.ToDotNetObject(_pemCert);
            bcCert = CertUtils.ToBouncyCastleObject(dotNetCert);
            Assert.IsTrue(bcCert != null);
        }

        /// <summary>
        /// Tests certificate conversion to DER encoded byte array
        /// </summary>
        [Test()]
        public void ConvertToDerEncodedByteArray()
        {
            byte[] derCert = null;
            X509Certificate2 dotNetCert = null;
            BCX509.X509Certificate bcCert = null;

            // From BouncyCastleObject
            try
            {
                derCert = CertUtils.ToDerEncodedByteArray((BCX509.X509Certificate)null);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentNullException);
            }

            bcCert = CertUtils.ToBouncyCastleObject(_derCert);
            derCert = CertUtils.ToDerEncodedByteArray(bcCert);
            Assert.IsTrue(Convert.ToBase64String(derCert) == Convert.ToBase64String(_derCert));

            bcCert = CertUtils.ToBouncyCastleObject(_pemCert);
            derCert = CertUtils.ToDerEncodedByteArray(bcCert);
            Assert.IsTrue(Convert.ToBase64String(derCert) == Convert.ToBase64String(_derCert));

            // From DotNetObject
            try
            {
                derCert = CertUtils.ToDerEncodedByteArray((X509Certificate2)null);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentNullException);
            }

            dotNetCert = CertUtils.ToDotNetObject(_derCert);
            derCert = CertUtils.ToDerEncodedByteArray(dotNetCert);
            Assert.IsTrue(Convert.ToBase64String(derCert) == Convert.ToBase64String(_derCert));

            dotNetCert = CertUtils.ToDotNetObject(_pemCert);
            derCert = CertUtils.ToDerEncodedByteArray(dotNetCert);
            Assert.IsTrue(Convert.ToBase64String(derCert) == Convert.ToBase64String(_derCert));
        }

        /// <summary>
        /// Tests IsSelfSigned method of CertUtils class
        /// </summary>
        [Test()]
        public void IsSelfSignedTest()
        {
            BCX509.X509Certificate bcCert = CertUtils.ToBouncyCastleObject(_rootCA);
            Assert.IsTrue(CertUtils.IsSelfSigned(bcCert));

            bcCert = CertUtils.ToBouncyCastleObject(_subCA);
            Assert.IsFalse(CertUtils.IsSelfSigned(bcCert));
        }

        /// <summary>
        /// Tests BuildCertPath method of CertUtils class
        /// </summary>
        [Test()]
        public void BuildCertPathTest()
        {
            List<byte[]> otherCerts = null;
            ICollection<BCX509.X509Certificate> certPath = null;

            // Self-signed signing certificate
            certPath = CertUtils.BuildCertPath(_derCert, otherCerts);
            Assert.IsTrue(certPath.Count == 1);
            Assert.IsTrue(Convert.ToBase64String(GetCertAt(certPath, 0).GetEncoded()) == Convert.ToBase64String(_derCert));

            // Path cannot be built when signing certificate is not self-signed and no additional certs are provided
            try
            {
                certPath = CertUtils.BuildCertPath(_endEntity, otherCerts);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Org.BouncyCastle.Pkix.PkixCertPathBuilderException);
            }

            // Fails when additional certs are provided and the path cannot be build because root CA is missing
            try
            {
                otherCerts = new List<byte[]>();
                otherCerts.Add(_subCA);
                certPath = CertUtils.BuildCertPath(_endEntity, otherCerts);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Org.BouncyCastle.Pkix.PkixCertPathBuilderException);
            }

            // Fails when additional certs are provided and the path cannot be build because intermediate CA is missing
            try
            {
                otherCerts = new List<byte[]>();
                otherCerts.Add(_rootCA);
                certPath = CertUtils.BuildCertPath(_endEntity, otherCerts);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Org.BouncyCastle.Pkix.PkixCertPathBuilderException);
            }

            // Returns full chain when the path can be built
            otherCerts = new List<byte[]>();
            otherCerts.Add(_rootCA);
            otherCerts.Add(_subCA);
            certPath = CertUtils.BuildCertPath(_endEntity, otherCerts);
            Assert.IsTrue(certPath.Count == 3);
            Assert.IsTrue(Convert.ToBase64String(GetCertAt(certPath, 0).GetEncoded()) == Convert.ToBase64String(_endEntity));
            Assert.IsTrue(Convert.ToBase64String(GetCertAt(certPath, 1).GetEncoded()) == Convert.ToBase64String(_subCA));
            Assert.IsTrue(Convert.ToBase64String(GetCertAt(certPath, 2).GetEncoded()) == Convert.ToBase64String(_rootCA));
        }

        /// <summary>
        /// Returns specific certificate from collection
        /// </summary>
        /// <param name="certPath">Collection of certificates</param>
        /// <param name="index">Index of certificate that should be returned</param>
        /// <returns>Specific certificate from collection</returns>
        private BCX509.X509Certificate GetCertAt(ICollection<BCX509.X509Certificate> certPath, int index)
        {
            if (certPath == null)
                throw new ArgumentNullException("certPath");

            if (index < 0 || index > (certPath.Count - 1))
                throw new ArgumentOutOfRangeException("index");

            int i = 0;
            foreach (BCX509.X509Certificate cert in certPath)
            {
                if (index == i)
                    return cert;
                else
                    i++;
            }

            throw new ArgumentOutOfRangeException("index");
        }
    }
}
