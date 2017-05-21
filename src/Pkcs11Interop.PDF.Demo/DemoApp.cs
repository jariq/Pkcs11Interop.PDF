/*
 *  Pkcs11Interop.PDF.Demo - Demonstration application
 *                           for Pkcs11Interop.PDF library
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
using System.IO;
using System.Security.Cryptography.X509Certificates;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Net.Pkcs11Interop.Common;
using Org.BouncyCastle.Crypto.Parameters;

namespace Net.Pkcs11Interop.PDF
{
    /// <summary>
    /// Demonstration application for Pkcs11Interop.PDF library
    /// </summary>
    static class DemoApp
    {
        /// <summary>
        /// Exit code indicating success
        /// </summary>
        const int _exitSuccess = 0;

        /// <summary>
        /// Exit code indicating error
        /// </summary>
        const int _exitError = 1;

        /// <summary>
        /// Command line argument that specifies pkcs11 library path
        /// </summary>
        const string _argPkcs11Library = "--pkcs11-library";

        /// <summary>
        /// Command line argument that enables mode which lists all available tokens
        /// </summary>
        const string _argListTokens = "--list-tokens";

        /// <summary>
        /// Command line argument that enables mode which lists available objects on specified token
        /// </summary>
        const string _argListObjects = "--list-objects";

        /// <summary>
        /// Command line argument that enables mode which signs specified PDF document
        /// </summary>
        const string _argSign = "--sign";

        /// <summary>
        /// Command line argument that specifies token serial number
        /// </summary>
        const string _argTokenSerial = "--token-serial";

        /// <summary>
        /// Command line argument that specifies token label
        /// </summary>
        const string _argTokenLabel = "--token-label";

        /// <summary>
        /// Command line argument that specifies user PIN
        /// </summary>
        const string _argPin = "--pin";

        /// <summary>
        /// Command line argument that specifies key label (value of CKA_LABEL attribute)
        /// </summary>
        const string _argKeyLabel = "--key-label";

        /// <summary>
        /// Command line argument that specifies hex encoded key identifier (value of CKA_ID attribute)
        /// </summary>
        const string _argKeyId = "--key-id";

        /// <summary>
        /// Command line argument that specifies input PDF file for signing
        /// </summary>
        const string _argInputPdf = "--input-pdf";

        /// <summary>
        /// Command line argument that specifies output PDF file for signing
        /// </summary>
        const string _argOutputPdf = "--output-pdf";

        /// <summary>
        /// Command line argument that specifies signing digest algorithm
        /// </summary>
        const string _argHashAlg = "--hash-alg";

        /// <summary>
        /// Command line argument that specifies path to the directory with additional certificates for certification path building
        /// </summary>
        const string _argCertsDir = "--certs-dir";

        /// <summary>
        /// Main method specifying where program execution is to begin
        /// </summary>
        /// <param name="args">Command line arguments passed to the program</param>
        static void Main(string[] args)
        {
            try
            {
                // Parse command line arguments
                string pkcs11Library = null;
                int listTokens = 0;
                int listObjects = 0;
                int sign = 0;
                string tokenSerial = null;
                string tokenLabel = null;
                string pin = null;
                string keyLabel = null;
                string keyId = null;
                string inputPdf = null;
                string outputPdf = null;
                string hashAlg = null;
                string certsDir = null;

                if (args.Length == 0)
                    ExitWithHelp(null);

                int i = 0;
                while (i < args.Length)
                {
                    switch (args[i])
                    {
                        case _argPkcs11Library:
                            pkcs11Library = args[++i];
                            break;
                        case _argListTokens:
                            listTokens = 1;
                            break;
                        case _argListObjects:
                            listObjects = 1;
                            break;
                        case _argSign:
                            sign = 1;
                            break;
                        case _argTokenSerial:
                            tokenSerial = args[++i];
                            break;
                        case _argTokenLabel:
                            tokenLabel = args[++i];
                            break;
                        case _argPin:
                            pin = args[++i];
                            break;
                        case _argKeyLabel:
                            keyLabel = args[++i];
                            break;
                        case _argKeyId:
                            keyId = args[++i];
                            break;
                        case _argInputPdf:
                            inputPdf = args[++i];
                            break;
                        case _argOutputPdf:
                            outputPdf = args[++i];
                            break;
                        case _argHashAlg:
                            hashAlg = args[++i];
                            break;
                        case _argCertsDir:
                            certsDir = args[++i];
                            break;
                        default:
                            ExitWithHelp("Invalid argument: " + args[i]);
                            break;
                    }

                    i++;
                }

                // Validate operation modes
                if (listTokens + listObjects + sign != 1)
                    ExitWithHelp(string.Format("Argument \"{0}\", \"{1}\" or \"{2}\" has to be specified", _argListTokens, _argListObjects, _argSign));

                // Handle "--list-tokens" operation mode
                if (listTokens == 1)
                {
                    // Validate command line arguments
                    if (string.IsNullOrEmpty(pkcs11Library))
                        ExitWithHelp("Required argument: " + _argPkcs11Library);
                    if (!string.IsNullOrEmpty(tokenSerial))
                        ExitWithHelp("Unexpected argument: " + _argTokenSerial);
                    if (!string.IsNullOrEmpty(tokenLabel))
                        ExitWithHelp("Unexpected argument: " + _argTokenLabel);
                    if (!string.IsNullOrEmpty(pin))
                        ExitWithHelp("Unexpected argument: " + _argPin);
                    if (!string.IsNullOrEmpty(keyLabel))
                        ExitWithHelp("Unexpected argument: " + _argKeyLabel);
                    if (!string.IsNullOrEmpty(keyId))
                        ExitWithHelp("Unexpected argument: " + _argKeyId);
                    if (!string.IsNullOrEmpty(inputPdf))
                        ExitWithHelp("Unexpected argument: " + _argInputPdf);
                    if (!string.IsNullOrEmpty(outputPdf))
                        ExitWithHelp("Unexpected argument: " + _argOutputPdf);
                    if (!string.IsNullOrEmpty(hashAlg))
                        ExitWithHelp("Unexpected argument: " + _argHashAlg);
                    if (!string.IsNullOrEmpty(certsDir))
                        ExitWithHelp("Unexpected argument: " + _argCertsDir);

                    // Perform requested operation
                    using (Pkcs11Explorer pkcs11Explorer = new Pkcs11Explorer(pkcs11Library))
                    {
                        Console.WriteLine("Listing available tokens");

                        int j = 1;
                        List<Token> tokens = pkcs11Explorer.GetTokens();
                        foreach (Token token in tokens)
                        {
                            Console.WriteLine();
                            Console.WriteLine("Token no." + j);
                            Console.WriteLine("  Manufacturer:       " + token.ManufacturerId);
                            Console.WriteLine("  Model:              " + token.Model);
                            Console.WriteLine("  Serial number:      " + token.SerialNumber);
                            Console.WriteLine("  Label:              " + token.Label);
                            j++;
                        }
                    }
                }

                // Handle "--list-objects" operation mode
                if (listObjects == 1)
                {
                    // Validate command line arguments
                    if (string.IsNullOrEmpty(pkcs11Library))
                        ExitWithHelp("Required argument: " + _argPkcs11Library);
                    if (string.IsNullOrEmpty(tokenSerial) && string.IsNullOrEmpty(tokenLabel))
                        ExitWithHelp("Required argument: " + _argTokenSerial + " and/or " + _argTokenLabel);
                    if (string.IsNullOrEmpty(pin))
                        ExitWithHelp("Required argument: " + _argPin);
                    if (!string.IsNullOrEmpty(keyLabel))
                        ExitWithHelp("Unexpected argument: " + _argKeyLabel);
                    if (!string.IsNullOrEmpty(keyId))
                        ExitWithHelp("Unexpected argument: " + _argKeyId);
                    if (!string.IsNullOrEmpty(inputPdf))
                        ExitWithHelp("Unexpected argument: " + _argInputPdf);
                    if (!string.IsNullOrEmpty(outputPdf))
                        ExitWithHelp("Unexpected argument: " + _argOutputPdf);
                    if (!string.IsNullOrEmpty(hashAlg))
                        ExitWithHelp("Unexpected argument: " + _argHashAlg);
                    if (!string.IsNullOrEmpty(certsDir))
                        ExitWithHelp("Unexpected argument: " + _argCertsDir);

                    // Perform requested operation
                    using (Pkcs11Explorer pkcs11Explorer = new Pkcs11Explorer(pkcs11Library))
                    {
                        Console.WriteLine(string.Format("Listing objects available on token with serial \"{0}\" and label \"{1}\"", tokenSerial, tokenLabel));

                        // Find requested token
                        Token foundToken = null;

                        List<Token> tokens = pkcs11Explorer.GetTokens();
                        foreach (Token token in tokens)
                        {
                            if (!string.IsNullOrEmpty(tokenLabel))
                                if (0 != String.Compare(tokenLabel, token.Label, StringComparison.InvariantCultureIgnoreCase))
                                    continue;

                            if (!string.IsNullOrEmpty(tokenSerial))
                                if (0 != String.Compare(tokenSerial, token.SerialNumber, StringComparison.InvariantCultureIgnoreCase))
                                    continue;

                            foundToken = token;
                            break;
                        }

                        if (foundToken == null)
                            throw new TokenNotFoundException(string.Format("Token with serial \"{0}\" and label \"{1}\" was not found", tokenSerial, tokenLabel));

                        // Get private keys and certificates stored in requested token
                        List<PrivateKey> privateKeys = null;
                        List<Certificate> certificates = null;
                        pkcs11Explorer.GetTokenObjects(foundToken, true, pin, out privateKeys, out certificates);

                        // Print private keys
                        int j = 1;
                        foreach (PrivateKey privateKey in privateKeys)
                        {
                            Console.WriteLine();
                            Console.WriteLine("Private key #" + j);

                            int[] matchingCertIds = GetMatchingCertIds(privateKey, certificates);
                            Console.WriteLine("  Matching certs:     " + PrintMatchingIds(matchingCertIds));

                            Console.WriteLine("  ID (CKA_ID):        " + privateKey.Id);
                            Console.WriteLine("  Label (CKA_LABEL):  " + privateKey.Label);

                            // Print public part of RSA key
                            if ((privateKey.PublicKey != null) && (privateKey.PublicKey is RsaKeyParameters))
                            {
                                RsaKeyParameters rsa = privateKey.PublicKey as RsaKeyParameters;
                                Console.WriteLine("  RSA exponent:       " + ConvertUtils.BytesToHexString(rsa.Exponent.ToByteArrayUnsigned()));
                                Console.WriteLine("  RSA public modulus: " + ConvertUtils.BytesToHexString(rsa.Modulus.ToByteArrayUnsigned()));
                            }

                            j++;
                        }

                        // Print certificates
                        int k = 1;
                        foreach (Certificate certificate in certificates)
                        {
                            Console.WriteLine();
                            Console.WriteLine("Certificate #" + k);

                            int[] matchingKeyIds = GetMatchingKeyIds(certificate, privateKeys);
                            Console.WriteLine("  Matching keys:      " + PrintMatchingIds(matchingKeyIds));

                            X509Certificate2 x509Cert = CertUtils.ToDotNetObject(certificate.Data);

                            Console.WriteLine("  ID (CKA_ID):        " + certificate.Id);
                            Console.WriteLine("  Label (CKA_LABEL):  " + certificate.Label);
                            Console.WriteLine("  Serial number:      " + x509Cert.SerialNumber);
                            Console.WriteLine("  Subject DN:         " + x509Cert.Subject);
                            Console.WriteLine("  Issuer DN:          " + x509Cert.Issuer);
                            Console.WriteLine("  Not before:         " + x509Cert.NotBefore);
                            Console.WriteLine("  Not after:          " + x509Cert.NotAfter);

                            // Print certified public RSA key
                            if ((certificate.PublicKey != null) && (certificate.PublicKey is RsaKeyParameters))
                            {
                                RsaKeyParameters rsa = certificate.PublicKey as RsaKeyParameters;
                                Console.WriteLine("  RSA exponent:       " + ConvertUtils.BytesToHexString(rsa.Exponent.ToByteArrayUnsigned()));
                                Console.WriteLine("  RSA public modulus: " + ConvertUtils.BytesToHexString(rsa.Modulus.ToByteArrayUnsigned()));
                            }

                            k++;
                        }
                    }
                }

                // Handle "--sign" operation mode
                if (sign == 1)
                {
                    // Use SHA256 as default hashing algorithm
                    HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

                    // Validate command line arguments (_argHashAlg and _argCertsDir are optional)
                    if (string.IsNullOrEmpty(pkcs11Library))
                        ExitWithHelp("Required argument: " + _argPkcs11Library);
                    if (string.IsNullOrEmpty(tokenSerial) && string.IsNullOrEmpty(tokenLabel))
                        ExitWithHelp("Required argument: " + _argTokenSerial + " and/or " + _argTokenLabel);
                    if (string.IsNullOrEmpty(pin))
                        ExitWithHelp("Required argument: " + _argPin);
                    if (string.IsNullOrEmpty(keyLabel) && string.IsNullOrEmpty(keyId))
                        ExitWithHelp("Required argument: " + _argKeyLabel + " and/or " + _argKeyId);
                    if (string.IsNullOrEmpty(inputPdf))
                        ExitWithHelp("Required argument: " + _argInputPdf);
                    if (string.IsNullOrEmpty(outputPdf))
                        ExitWithHelp("Required argument: " + _argOutputPdf);
                    if (!string.IsNullOrEmpty(hashAlg))
                        hashAlgorithm = (HashAlgorithm)Enum.Parse(typeof(HashAlgorithm), hashAlg);

                    // Perform requested operation
                    using (Pkcs11RsaSignature pkcs11RsaSignature = new Pkcs11RsaSignature(pkcs11Library, tokenSerial, tokenLabel, pin, keyLabel, keyId, hashAlgorithm))
                    {
                        Console.WriteLine(string.Format("Signing PDF document \"{0}\" using private key with ID \"{1}\" and label \"{2}\" stored on token with serial \"{3}\" and label \"{4}\"", inputPdf, keyId, keyLabel, tokenSerial, tokenLabel));

                        // Read signing certificate from the token
                        byte[] signingCertificate = pkcs11RsaSignature.GetSigningCertificate();

                        // Read all certificates stored on the token
                        List<byte[]> otherCertificates = pkcs11RsaSignature.GetAllCertificates();

                        // Read additional certificates from directory
                        if (!string.IsNullOrEmpty(certsDir))
                            foreach (string file in Directory.GetFiles(certsDir))
                                otherCertificates.Add(File.ReadAllBytes(file));

                        // Build certification path for the signing certificate
                        ICollection<Org.BouncyCastle.X509.X509Certificate> certPath = CertUtils.BuildCertPath(signingCertificate, otherCertificates);

                        // Read unsigned PDF document
                        using (PdfReader pdfReader = new PdfReader(inputPdf))
                        {
                            // Create output stream for signed PDF document
                            using (FileStream outputStream = new FileStream(outputPdf, FileMode.Create))
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
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(@"Operation error: " + ex.GetType() + " - " + ex.Message);
                Console.WriteLine(ex.StackTrace);
                Environment.Exit(_exitError);
            }

            Environment.Exit(_exitSuccess);
        }

        /// <summary>
        /// Identifies certificates matching specified private key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <param name="certificates">Certificates that should be analyzed</param>
        /// <returns>Indexes of matching certificates</returns>
        static int[] GetMatchingCertIds(PrivateKey privateKey, List<Certificate> certificates)
        {
            List<int> indexes = new List<int>();

            int i = 1;

            foreach (Certificate certificate in certificates)
            {
                bool? matches = privateKey.Matches(certificate);

                if (matches.HasValue && matches.Value == true)
                    indexes.Add(i);

                i++;
            }

            return indexes.ToArray();
        }

        /// <summary>
        /// Identifies private keys matching specified certificate
        /// </summary>
        /// <param name="certificate">Certificate</param>
        /// <param name="privateKeys">Private keys that should be analyzed</param>
        /// <returns>Indexes of matching private keys</returns>
        static int[] GetMatchingKeyIds(Certificate certificate, List<PrivateKey> privateKeys)
        {
            List<int> indexes = new List<int>();

            int i = 1;

            foreach (PrivateKey privateKey in privateKeys)
            {
                bool? matches = certificate.Matches(privateKey);

                if (matches.HasValue && matches.Value == true)
                    indexes.Add(i);

                i++;
            }

            return indexes.ToArray();
        }

        /// <summary>
        /// Converts indexes of matching objects to a printable form
        /// </summary>
        /// <param name="ids">Indexes of matching objects</param>
        /// <returns>Printable form of matching objects indexes</returns>
        static string PrintMatchingIds(int[] ids)
        {
            if (ids == null || ids.Length < 1)
                return "None";

            string output = null;

            foreach (int id in ids)
                output = "#" + id.ToString() + " ";

            return output;
        }

        /// <summary>
        /// Prints program usage and exits application
        /// </summary>
        /// <param name="error">Error message to be printed or null</param>
        static void ExitWithHelp(string error)
        {
            if (string.IsNullOrEmpty(error))
            {
                Console.WriteLine(@"Demonstration application for Pkcs11Interop.PDF library");
                Console.WriteLine(@"Copyright (c) 2013-2017 JWC s.r.o. <http://www.jwc.sk>");
                Console.WriteLine(@"Author: Jaroslav Imrich <jimrich@jimrich.sk>");
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine(@"Argument error: " + error);
                Console.WriteLine();
            }

            Console.WriteLine(@"Example usage:");
            Console.WriteLine();
            Console.WriteLine(@"  List available tokens (smartcards):");
            Console.WriteLine(@"    Pkcs11Interop.PDF.Demo.exe");
            Console.WriteLine(@"      --pkcs11-library ""siecap11.dll""");
            Console.WriteLine(@"      --list-tokens");
            Console.WriteLine();
            Console.WriteLine(@"  List private keys and certificates available on specified token (smartcard):");
            Console.WriteLine(@"    Pkcs11Interop.PDF.Demo.exe");
            Console.WriteLine(@"      --pkcs11-library ""siecap11.dll""");
            Console.WriteLine(@"      --list-objects");
            Console.WriteLine(@"      --token-serial ""7BFF2737350B262C""");
            Console.WriteLine(@"      --token-label ""Pkcs11Interop""");
            Console.WriteLine(@"      --pin ""11111111""");
            Console.WriteLine();
            Console.WriteLine(@"  Sign PDF document:");
            Console.WriteLine(@"    Pkcs11Interop.PDF.Demo.exe");
            Console.WriteLine(@"      --pkcs11-library ""siecap11.dll""");
            Console.WriteLine(@"      --sign");
            Console.WriteLine(@"      --token-serial ""7BFF2737350B262C""");
            Console.WriteLine(@"      --token-label ""Pkcs11Interop""");
            Console.WriteLine(@"      --pin ""11111111""");
            Console.WriteLine(@"      --key-label ""John Doe""");
            Console.WriteLine(@"      --key-id ""EC5E50A889B888D600C6E13CB0FDF0C1""");
            Console.WriteLine(@"      --input-pdf ""c:\temp\unsigned.pdf""");
            Console.WriteLine(@"      --output-pdf ""c:\temp\signed.pdf""");
            Console.WriteLine(@"      --hash-alg ""SHA256""");
            Console.WriteLine(@"      --certs-dir ""c:\temp\additional-certs""");

            Environment.Exit((string.IsNullOrEmpty(error)) ? _exitSuccess : _exitError);
        }
    }
}
