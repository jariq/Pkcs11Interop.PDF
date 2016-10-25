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

using System.Collections.Generic;
using System.IO;
using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using NUnit.Framework;

namespace Net.Pkcs11Interop.PDF.Tests
{
    /// <summary>
    /// Official code samples for Pkcs11Interop.PDF library
    /// </summary>
    [TestFixture()]
    public class Pkcs11RsaSignatureExample
    {
        /// <summary>
        /// Creates PKCS#1 v1.5 RSA signature of PDF document with the private key stored on PKCS#11 compatible device
        /// </summary>
        [Test()]
        public void SignPdfDocument()
        {
            // Specify path to the unsigned PDF that will be created by this code
            string unsignedPdfPath = @"c:\temp\unsigned.pdf";

            // Specify path to the signed PDF that will be created by this code
            string signedPdfPath = @"c:\temp\signed.pdf";

            // Create simple PDF document with iText
            using (Document document = new Document(PageSize.A4, 50, 50, 50, 50))
            {
                using (FileStream outputStream = new FileStream(unsignedPdfPath, FileMode.Create))
                {
                    using (PdfWriter pdfWriter = PdfWriter.GetInstance(document, outputStream))
                    {
                        document.Open();
                        document.Add(new Paragraph("Hello World!"));
                        document.Close();
                    }
                }
            }

            // Do something interesting with unsigned PDF document
            FileInfo unsignedPdfInfo = new FileInfo(unsignedPdfPath);
            Assert.IsTrue(unsignedPdfInfo.Length > 0);

            // Specify path to the unmanaged PCKS#11 library
            string libraryPath = @"siecap11.dll";

            // Specify serial number of the token that contains signing key. May be null if tokenLabel is specified.
            string tokenSerial = null;

            // Specify label of of the token that contains signing key. May be null if tokenSerial is specified
            string tokenLabel = @"Pkcs11Interop";

            // Specify PIN for the token
            string pin = @"11111111";

            // Specify label (value of CKA_LABEL attribute) of the private key used for signing. May be null if ckaId is specified.
            string ckaLabel = @"John Doe";

            // Specify hex encoded string with identifier (value of CKA_ID attribute) of the private key used for signing. May be null if ckaLabel is specified.
            string ckaId = null;

            // Specify hash algorihtm used for the signature creation
            HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

            // Create instance of Pkcs11Signature class that allows iText to create PKCS#1 v1.5 RSA signature with the private key stored on PKCS#11 compatible device
            using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(libraryPath, tokenSerial, tokenLabel, pin, ckaLabel, ckaId, hashAlgorithm))
            {
                // When signing certificate is stored on the token it can be usually read with GetSigningCertificate() method
                byte[] signingCertificate = pkcs11RsaSignature.GetSigningCertificate();

                // All certificates stored on the token can be usually read with GetAllCertificates() method
                List<byte[]> otherCertificates = pkcs11RsaSignature.GetAllCertificates();

                // Build certification path for the signing certificate
                ICollection<Org.BouncyCastle.X509.X509Certificate> certPath = CertUtils.BuildCertPath(signingCertificate, otherCertificates);

                // Read unsigned PDF document
                using (PdfReader pdfReader = new PdfReader(unsignedPdfPath))
                {
                    // Create output stream for signed PDF document
                    using (FileStream outputStream = new FileStream(signedPdfPath, FileMode.Create))
                    {
                        // Create PdfStamper that applies extra content to the PDF document
                        using (PdfStamper pdfStamper = PdfStamper.CreateSignature(pdfReader, outputStream, '\0', Path.GetTempFileName(), true))
                        {
                            // Sign PDF document
                            MakeSignature.SignDetached(pdfStamper.SignatureAppearance, pkcs11RsaSignature, certPath, null, null, null, 0, CryptoStandard.CADES);
                        }
                    }
                }
            }

            // Do something interesting with the signed PDF document
            FileInfo signedPdfInfo = new FileInfo(signedPdfPath);
            Assert.IsTrue(signedPdfInfo.Length > signedPdfPath.Length);
        }
    }
}
