/*! \mainpage Integration layer for Pkcs11Interop and iText (iTextSharp) libraries
 *
 * \tableofcontents
 * 
 * \section sec_overview Overview
 * 
 * <a href="http://sourceforge.net/projects/itextsharp/">iTextSharp</a> is a C# port of iText - an open-source Java library for PDF generation and manipulation. It can be used to create PDF documents from scratch, to convert XML to PDF, to fill out interactive PDF forms, to stamp new content on existing PDF documents, to split and merge existing PDF documents, to add digital signatures to PDF documents and much more.
 * 
 * <a href="http://www.pkcs11interop.net">Pkcs11interop</a> is managed library written in C# that brings full power of PKCS#11 API to the .NET environment. <a href="https://www.oasis-open.org/committees/pkcs11/">PKCS#11</a> is cryptography standard originally published by RSA Laboratories that defines ANSI C API to access smart cards and other types of cryptographic hardware. Pkcs11Interop uses System.Runtime.InteropServices to define platform invoke methods for accessing unmanaged PKCS#11 API and specifies how data is marshaled between managed and unmanaged memory. Pkcs11Interop library supports both 32-bit and 64-bit platforms and can be used with <a href="http://www.microsoft.com/net">.NET Framework</a> 2.0 or higher on Microsoft Windows or with <a href="http://www.mono-project.com/">Mono</a> on Linux, Mac OS X, BSD and others.
 *
 * <a href="https://github.com/jariq/Pkcs11Interop.PDF">Pkcs11interop.PDF</a> creates an integration layer between Pkcs11Interop and iTextSharp libraries by extending iTextSharp with the ability to digitally sign PDF document with the private key stored on almost any PKCS#11 compatible device.
 *
 * \section sec_recommended_reading Recommended reading
 * 
 * More general information about digital signatures in PDF documents can be found in a great white paper called &quot;<a href="http://itextpdf.com/book/digitalsignatures/">Digital Signatures for PDF documents</a>&quot; written by Bruno Lowagie from <a href="http://itextpdf.com/">iText Software</a>. There are also many useful code samples in <a href="http://svn.code.sf.net/p/itextsharp/code/tutorial">iTextSharp SVN repository</a>.
 * 
 * \section sec_code_samples Code samples
 * 
 * Pkcs11Interop.PDF source code contains well documented unit tests that also serve as <a href="examples.html">official code samples</a>.
 * 
 * <b>WARNING: Our documentation and code samples do not cover the theory of security/cryptography or the strengths/weaknesses of specific algorithms. You should always understand what you are doing and why. Please do not simply copy our code samples and expect it to fully solve your usage scenario. Cryptography is an advanced topic and one should consult a solid and preferably recent reference in order to make the best of it.</b>
 * 
 * \section sec_more_info More info
 * 
 * Please visit project website - <a href="http://www.pkcs11interop.net">www.pkcs11interop.net</a> - for more information regarding updates, licensing, support etc.
 */


/*! 
 * \namespace Net.Pkcs11Interop
 * \brief Base namespace of Pkcs11Interop project
 * 
 * \namespace Net.Pkcs11Interop.PDF
 * \brief Base namespace of Pkcs11Interop.PDF project
 */


/*!
 * \example Pkcs11RsaSignatureExample.cs
 */
