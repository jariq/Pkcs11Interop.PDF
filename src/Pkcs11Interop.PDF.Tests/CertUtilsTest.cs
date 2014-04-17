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
        byte[] _derCert = Convert.FromBase64String(@"MIIDOzCCAiOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBCMQswCQYDVQQGEwJTSzEgMB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxETAPBgNVBAMTCEpvaG4gRG9lMB4XDTEzMDUxODAwMDAwMFoXDTIzMDUxNzIzNTk1OVowQjELMAkGA1UEBhMCU0sxIDAeBgNVBAoTF1BrY3MxMUludGVyb3AuUERGLlRlc3RzMREwDwYDVQQDEwhKb2huIERvZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANhZegZNMKv1XKQTaif5o33leIDBiCgFNhqP0eDFlvGeLrESnh3GArbx+zMNSfPsfnqIfrcLvKTGR32HrLogKGCXaVBGN0nIV/o3iHNApROGOY+ekWQAOMfAvUDngYTGx340kwjPyRWmbCjxFY5jxRL3Npv9Dg8y4LBshGARY7JKqrSmpY1WPr9vEQcIox9HS/u9D51ZjB4kuvL5tnQh6pQeiOv94mAMK6+7nwSJFPUopqhb13qHfZytWepEJ6bfbOZZ4kwU9YSyH9R5V48UyfJhc0lFK5CNSbSCyl87qvUnhbSszPTEsL94dyy7bDVf8f1nMkyol63mAOQVGbC5pysCAwEAAaM8MDowDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUaMyotFLpVmy/5ldpUq7mwivA3pQwCwYDVR0PBAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IBAQBfhTjRrwqS0ShZWV17QAggM2PxHf/UCtdO8hBScWzh0CZy0uSElGz23q532kmaO1iZyng976RRX15TU6br1nAoI7OCvvfliVfxl5/ahW5U9VOKgVz2OKp6a6rRcpIiDRrDgohY+ffKOnCAdPyDYw0QYoNYXNarEdPTDrTyjP57HgHMTYBS26HyRDLt1jMxDkUBihMZ8/QmbYNF9MS3Xq9TCyHUaHnEr4tw10whNkSnFrhShhOCQmMBX991LPRejkMyYLfYQz12+7KAOQZEcda6mfNe/H96hXIjfmUNYQ7QAIOMmiES9tKBqUElkZE7LNyVClzZVJyPdAWoJa6lyu+Y");

        /// <summary>
        /// PEM encoded certificate
        /// </summary>
        byte[] _pemCert = ASCIIEncoding.ASCII.GetBytes(@"-----BEGIN CERTIFICATE-----
MIIDOzCCAiOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBCMQswCQYDVQQGEwJTSzEg
MB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxETAPBgNVBAMTCEpvaG4g
RG9lMB4XDTEzMDUxODAwMDAwMFoXDTIzMDUxNzIzNTk1OVowQjELMAkGA1UEBhMC
U0sxIDAeBgNVBAoTF1BrY3MxMUludGVyb3AuUERGLlRlc3RzMREwDwYDVQQDEwhK
b2huIERvZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANhZegZNMKv1
XKQTaif5o33leIDBiCgFNhqP0eDFlvGeLrESnh3GArbx+zMNSfPsfnqIfrcLvKTG
R32HrLogKGCXaVBGN0nIV/o3iHNApROGOY+ekWQAOMfAvUDngYTGx340kwjPyRWm
bCjxFY5jxRL3Npv9Dg8y4LBshGARY7JKqrSmpY1WPr9vEQcIox9HS/u9D51ZjB4k
uvL5tnQh6pQeiOv94mAMK6+7nwSJFPUopqhb13qHfZytWepEJ6bfbOZZ4kwU9YSy
H9R5V48UyfJhc0lFK5CNSbSCyl87qvUnhbSszPTEsL94dyy7bDVf8f1nMkyol63m
AOQVGbC5pysCAwEAAaM8MDowDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUaMyotFLp
Vmy/5ldpUq7mwivA3pQwCwYDVR0PBAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IBAQBf
hTjRrwqS0ShZWV17QAggM2PxHf/UCtdO8hBScWzh0CZy0uSElGz23q532kmaO1iZ
yng976RRX15TU6br1nAoI7OCvvfliVfxl5/ahW5U9VOKgVz2OKp6a6rRcpIiDRrD
gohY+ffKOnCAdPyDYw0QYoNYXNarEdPTDrTyjP57HgHMTYBS26HyRDLt1jMxDkUB
ihMZ8/QmbYNF9MS3Xq9TCyHUaHnEr4tw10whNkSnFrhShhOCQmMBX991LPRejkMy
YLfYQz12+7KAOQZEcda6mfNe/H96hXIjfmUNYQ7QAIOMmiES9tKBqUElkZE7LNyV
ClzZVJyPdAWoJa6lyu+Y
-----END CERTIFICATE-----");

        /// <summary>
        /// Arbitrary byte array 
        /// </summary>
        byte[] _noCert = ASCIIEncoding.ASCII.GetBytes(@"Hello world");

        /// <summary>
        /// Certificate of random self-signed Root CA
        /// </summary>
        byte[] _rootCA = Convert.FromBase64String(@"MIIDPDCCAiSgAwIBAgIBATANBgkqhkiG9w0BAQsFADBBMQswCQYDVQQGEwJTSzEgMB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxEDAOBgNVBAMTB1Jvb3QgQ0EwHhcNMTQwNDE3MDAwMDAwWhcNMjQwNDE2MjM1OTU5WjBBMQswCQYDVQQGEwJTSzEgMB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxEDAOBgNVBAMTB1Jvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1n8FPMzQ5iO6YccBt+ADf3BLH1QfhkpSSR61yd7P7YDlth9J5wIZPryXplS6yLsLiuyVV68LJkSJe3aCdAMxlb24b9NBXoGCFqBKRIYulIIrt0MSRzzNcv+oSwkvYRdPXzMT8u+sOxd23Ae74A/lRxOITlbgXeB4mVTOyIGkEBX3uSUyztHFhl0zbeK1qC+V2TPCOXe/lvANME8MtzY2aCuW37LQw214yP+Fy9qr82TR2qw6LEGFa+3+JpSEbc5oGH4zczvV3IsPObuu3MGV+s7CQBwmg7lrwWEWF06aOYjg/9Gj1bFR9O/pJXIueda33BtZkOsrpcr1v5aLxjKIXAgMBAAGjPzA9MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFJ5R3xfytXZEUgfU7bXw1var/WeqMAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAfjA7+iJqXcJtMYvTwho2wGKknicqrpNGcscR2VGPW5uALGvfhrPGazbtmbHvC8HLl+UwBOL70wQowkuNPUJxlZba9IxvdHMkTNmvww0iT8C05mRPrYIfdsUHw0pQbnWiX/z6jtc2P2JZruSB1+YZR3PJdCuGOayB0sVbnAqpiSU1KBIR1Pm3GPdIvsEeAXVH3oNb41r+7ju70AmB+5/Kkg2fnyPtBKTulSewXP/XIOlDl3i+jqgReJ6Mwe1aGgoMUMoVFVb7V2cllbApf2buSuhGWSeFv8zvo/wUEYya2O1SfAL512c7fBKo8duyW64+vUAFgBlfm4Hk2Y/t3blZog==");

        /// <summary>
        /// Certificate of random Intermediate CA signed by Root CA
        /// </summary>
        byte[] _subCA = Convert.FromBase64String(@"MIIDRDCCAiygAwIBAgIBAjANBgkqhkiG9w0BAQsFADBBMQswCQYDVQQGEwJTSzEgMB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxEDAOBgNVBAMTB1Jvb3QgQ0EwHhcNMTQwNDE3MDAwMDAwWhcNMjQwNDE2MjM1OTU5WjBJMQswCQYDVQQGEwJTSzEgMB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxGDAWBgNVBAMTD0ludGVybWVkaWF0ZSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMypYXBNs57UI97kA/lmBQC0+WSsTrWDaL2XWwvYGgS7MHbpMnrIH3Kn++YqkdsEom6Zb+EC8YLQRky2N91nb8KamB4JMGFOIifSLYIXsPrI0VvcHKophGr0/Y60WOQJ48NnpaLuAOf7PMhkIrOHec4uhOiDerukd9kOBuONvZajFgtNqSZUah79PW4U7OMsQpaBozT0K59HC41dx8fgIQ442g0pVW3nTXdg7iV/n9RoMZkC+sVsMCPE738krfAt3A7stKidJNu90RK7bdSedwHRCaUvtMRCAsTr8EhOFU8nbsdeubyx+X7uo/TDK03oSlwe63Jv9nV0PUrIxOx/neUCAwEAAaM/MD0wDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU+jbNpEDgfh4hlIOK4lgt2KTnFrMwCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQB3WTsQBX8yIiC/nLAiJfzHK1L7wSXnxEniZ9bOcP/iaVMVrn6Xzq2sXZl/E+DiHhmdXdgDZVi6kAcGQ/6Q7UaKrLKGitSeUdvkXD/T4r8/lehFRKr2IOx1PKYQDirtxNb1di+y/VQwKsIJHejtdYDuRdesLtMJff9uY0ZNGmKb+FSwxGtAXvbe53ISbsFb75MH/mM2WewnxWdVxcBPv+5pYDDO5tMYg8uAzmr8C6iC6Tk6GNB1pHxH2OCm0+Tq8T3JdI8JeiAMQa0RxHMrOWd4Ti58KthGfJwSUIDlgY7+JuxWMEEDRCwh2BmMBzjvMIqR+2G6ObPvjwpbw82uPlkZ");

        /// <summary>
        /// Certificate of random End Entity signed by Intermediate CA
        /// </summary>
        byte[] _endEntity = Convert.FromBase64String(@"MIIDRDCCAiygAwIBAgIBAzANBgkqhkiG9w0BAQsFADBJMQswCQYDVQQGEwJTSzEgMB4GA1UEChMXUGtjczExSW50ZXJvcC5QREYuVGVzdHMxGDAWBgNVBAMTD0ludGVybWVkaWF0ZSBDQTAeFw0xNDA0MTcwMDAwMDBaFw0xNTA0MTYyMzU5NTlaMEQxCzAJBgNVBAYTAlNLMSAwHgYDVQQKExdQa2NzMTFJbnRlcm9wLlBERi5UZXN0czETMBEGA1UEAxMKRW5kIEVudGl0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALD5OlZaIVMLhRzrrQDyZCdH33IeRlN3kSj+k6gyOEr3AxQrxosC050HuN4YiIfOpVAexHGcja5dP7XMrWgM4gqlHE7LxYLZKtwQ4Qse9lenZPh/h2CKP2D5PewiWXMEJydo0x54GnQ3b/AEnUut/vt/a4t0pFtXh3+JLPxKCc9IQsDzVd8h/vt+iEROfufPLaeWUVIF2Am+/FXuSKhETpQVKjtrXISibZ1rQHPWNZrpi5w0hDS4lMOC6/kFQnZN/AwyI+xlmxsE17dpjn4juDHCCP9JpQaOSZGnRNwqdUzbcS7kin0NOfH2G+HxEomYpeKVxZgwoGzecW9Hg9C8be8CAwEAAaM8MDowDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUkgSb3Ko0582i4xrOz4R8Tz7jVcYwCwYDVR0PBAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IBAQB5wfbWLzX6EYCMWBMMM4tGzSYEZkWQiz3sblyM84J2WVbSJi5JDs9ugvuJU210wdooxsln/1F2BL3Lc8pBdolUV6MNY2RcEWmT+1ngQUsuH1BDhMY6Pmgf4/TYMHlmcN1mKowyw1NtPTZclng/4yI7vBhhi0KqzsiNduQrIYuHe81qBgZdtab4G+MCB53gh2yhdCd3N8oSHD5juuZorJdczkqmxsAp3/G9f6c4i+QmgxEehw1XW5JklKJVI4CnOo9JZYa9XMSC+UsRDRl3UJKp78bbQ75m5HtIZ6Wc4An7wNfEUu+yVcDkR/93TX6SsTn+PSgTZoQNlHeDZfiXICaB");

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
