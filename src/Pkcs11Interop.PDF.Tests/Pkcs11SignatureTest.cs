/*
 *  Pkcs11Interop.PDF - Integration layer for Pkcs11Interop
 *                      and iText (iTextSharp) libraries
 *  Copyright (c) 2013 JWC s.r.o.
 *  Author: Jaroslav Imrich
 *  
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License version 3
 *  as published by the Free Software Foundation.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Affero General Public License for more details.
 *  
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 *  
 *  You can be released from the requirements of the license by purchasing
 *  a commercial license. Buying such a license is mandatory as soon as you
 *  develop commercial activities involving the Pkcs11Interop.PDF software without
 *  disclosing the source code of your own applications.
 *  
 *  For more information, please contact JWC s.r.o. at info@pkcs11interop.net
 */

using System;
using System.Collections.Generic;
using System.IO;
using NUnit.Framework;
using Net.Pkcs11Interop.PDF;
using Org.BouncyCastle.X509;
using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;

namespace Net.Pkcs11Interop.PDF.Tests
{
	/// <summary>
	/// PDF signature creation tests.
	/// </summary>
	[TestFixture()]
	public class Pkcs11SignatureTest
	{
		#region Test settings

		/// <summary>
		/// Path to the unsigned PDF that will be created by this test
		/// </summary>
		// Path to the unsigned PDF that will be created by this test
		public static string unsignedPdf = @"c:\Pkcs11Interop.PDF.Tests\unsigned.pdf";

		/// <summary>
		/// Path to the signed PDF that will be created by this test
		/// </summary>
		// Path to the signed PDF that will be created by this test
		public static string signedPdf = @"c:\Pkcs11Interop.PDF.Tests\signed.pdf";

		/// <summary>
		/// Path to the unmanaged PCKS#11 library
		/// </summary>
		// Path to the unmanaged PCKS#11 library
		public static string libraryPath = @"siecap11.dll";

		/// <summary>
		/// Serial number of the token (smartcard) that contains signing key. May be null if tokenLabel is specified.
		/// </summary>
		// Serial number of the token (smartcard) that contains signing key. May be null if tokenLabel is specified.
		public static string tokenSerial = null;

		/// <summary>
		/// Label of of the token (smartcard) that contains signing key. May be null if tokenSerial is specified.
		/// </summary>
		// Label of of the token (smartcard) that contains signing key. May be null if tokenSerial is specified.
		public static string tokenLabel = @"Pkcs11Interop";

		/// <summary>
		/// PIN for the token (smartcard)
		/// </summary>
		// PIN for the token (smartcard)
		public static string pin = @"11111111";

		/// <summary>
		/// Label (value of CKA_LABEL attribute) of the private key used for signing. May be null if ckaId is specified.
		/// </summary>
		// Label (value of CKA_LABEL attribute) of the private key used for signing. May be null if ckaId is specified.
		public static string ckaLabel = @"John Doe";

		/// <summary>
		/// Hex encoded string with identifier (value of CKA_ID attribute) of the private key used for signing. May be null if ckaLabel is specified.
		/// </summary>
		// Hex encoded string with identifier (value of CKA_ID attribute) of the private key used for signing. May be null if ckaLabel is specified.
		public static string ckaId = null;

		/// <summary>
		/// Hash algorihtm used for the signature creation
		/// </summary>
		// Hash algorihtm used for the signature creation
		public static HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

		#endregion

		/// <summary>
		/// PDF signature creation with RSA private key stored on PKCS#11 compatible device test.
		/// </summary>
		// PDF signature creation with RSA private key stored on PKCS#11 compatible device test.
		[Test()]
		public void SignPdfTest()
		{
			// Use iText to create unsigned PDF document
			using (Document document = new Document(PageSize.A4, 50, 50, 50, 50))
			{
				using (FileStream outputStream = new FileStream(unsignedPdf, FileMode.Create))
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
			FileInfo unsignedPdfInfo = new FileInfo(unsignedPdf);
			Assert.IsTrue(unsignedPdfInfo.Length > 0);

			// Create instance of Pkcs11Signature class that acts as integration layer for Pkcs11Interop and iText (iTextSharp) libraries
			using (Pkcs11Signature pkcs11Signature = new Pkcs11Signature(libraryPath, tokenSerial, tokenLabel, pin, ckaLabel, ckaId, hashAlgorithm))
			{
				// This test uses self-signed certificate so it is the only certificate in chain
				ICollection<X509Certificate> certificateChain = new List<X509Certificate>();
				certificateChain.Add(pkcs11Signature.GetCertificateAsX509Certificate());

				// Read unsigned PDF document
				using (PdfReader pdfReader = new PdfReader(unsignedPdf))
				{
					// Create output stream for signed PDF document
					using (FileStream outputStream = new FileStream(signedPdf, FileMode.Create))
					{
						// Create PdfStamper that applies extra content to the pages of a PDF document
						using (PdfStamper pdfStamper = PdfStamper.CreateSignature(pdfReader, outputStream, '\0'))
						{
							// Sign PDF document
							MakeSignature.SignDetached(pdfStamper.SignatureAppearance, pkcs11Signature, certificateChain, null, null, null, 0, CryptoStandard.CADES);
						}
					}
				}
			}

			// Do something interesting with signed PDF document
			FileInfo signedPdfInfo = new FileInfo(signedPdf);
			Assert.IsTrue(signedPdfInfo.Length > unsignedPdf.Length);
		}
	}
}
