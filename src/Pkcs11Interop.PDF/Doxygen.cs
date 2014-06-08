/*! \mainpage Integration layer for Pkcs11Interop and iText (iTextSharp) libraries
 *
 * \tableofcontents
 * 
 * \section sec_quick_facts Quick facts
 * 
 * Pkcs11Interop.PDF is managed library that:
 * - enables iTextSharp to digitally sign PDF document with smartcard or any other PKCS#11 compatible device
 * - is compatible with .NET Framework and Mono
 * - is supported on Windows, Linux and Mac OS X
 * - is supported on both 32-bit and 64-bit platforms
 * - is available under open-source or commercial license
 * - uses 100% managed and fully documented code
 * - is directly supported by its original developer
 * 
 * \section sec_overview Overview
 * 
 * <a href="http://sourceforge.net/projects/itextsharp/">iTextSharp</a> is a C# port of iText - an open-source Java library for PDF generation and manipulation. It can be used to create PDF documents from scratch, to convert XML to PDF, to fill out interactive PDF forms, to stamp new content on existing PDF documents, to split and merge existing PDF documents, to add digital signatures to PDF documents and much more.
 * 
 * <a href="http://www.pkcs11interop.net">Pkcs11interop</a> is managed library written in C# that brings full power of PKCS#11 API to the .NET environment. <a href="https://www.oasis-open.org/committees/pkcs11/">PKCS#11</a> is cryptography standard originally published by RSA Laboratories that defines ANSI C API to access smart cards and other types of cryptographic hardware. Standard is currently being maintained and developed by the OASIS PKCS 11 Technical Committee.
 *
 * <a href="https://github.com/jariq/Pkcs11Interop.PDF">Pkcs11interop.PDF</a> creates an integration layer between Pkcs11Interop and iTextSharp libraries by extending iTextSharp with the ability to digitally sign PDF document with the private key stored on almost any PKCS#11 compatible device.
 *
 * \section sec_documentation Documentation
 * 
 * Pkcs11Interop.PDF API is fully documented with inline XML documentation that can be displayed by your IDE while you develop your application. Detailed <a href="annotated.html">Pkcs11Interop.PDF API documentation</a> is also available online.
 * 
 * General information about digital signatures in PDF documents can be found in a great white paper called &quot;<a href="http://itextpdf.com/book/digitalsignatures/">Digital Signatures for PDF documents</a>&quot; written by Bruno Lowagie from <a href="http://itextpdf.com/">iText Software</a>. There are also many useful code samples in <a href="http://svn.code.sf.net/p/itextsharp/code/tutorial">iTextSharp SVN repository</a>.
 * 
 * \section sec_code_samples Code samples
 * 
 * Pkcs11Interop.PDF source code contains well documented unit tests and demonstration command line application that also serve as <a href="examples.html">official code samples</a>.
 * 
 * \section sec_download Download
 * 
 * Pkcs11Interop.PDF can be obtained from the following sources:
 * 
 * - Binaries are available in the form of NuGet package:<br/>
 * <a href="https://www.nuget.org/packages/Pkcs11Interop.PDF/">https://www.nuget.org/packages/Pkcs11Interop.PDF/</a>
 * - Archives with source code can be downloaded from sourceforge.net:<br/>
 * <a href="https://sourceforge.net/projects/pkcs11interop/">https://sourceforge.net/projects/pkcs11interop/</a>
 * - Current development version can be viewed on GitHub:<br/>
 * <a href="https://github.com/jariq/Pkcs11Interop.PDF">https://github.com/jariq/Pkcs11Interop.PDF</a>
 * 
 * Archives with the source code as well as the assemblies in NuGet package are digitally signed by <a href="http://crypto.jimrich.sk/">Jaroslav Imrich</a>.
 * 
 * \section sec_license License
 * 
 * Pkcs11Interop.PDF uses dual-licensing model:</p>
 * 
 * - <b>Licensing for open source projects:</b><br/>
 * Pkcs11Interop.PDF is available under the terms of the <a href="http://www.gnu.org/licenses/agpl-3.0.html">GNU Affero General Public License version 3</a> as published by the Free Software Foundation.
 * - <b>Licensing for other types of projects:</b><br/>
 * Pkcs11Interop.PDF is available under the terms of flexible commercial license. Please contact JWC s.r.o. at <a href="mailto:info@pkcs11interop.net">info@pkcs11interop.net</a> for more details.
 * 
 * \section sec_support Support
 * 
 * Pkcs11Interop.PDF is supported via the following channels:</p>
 * 
 * - General purpose mailing list with <a href="https://groups.google.com/d/forum/pkcs11interop">the online archive</a>:<br/>
 * <a href="mailto:pkcs11interop@googlegroups.com">pkcs11interop@googlegroups.com</a>
 * - Public issue tracker on GitHub:<br/>
 * <a href="https://github.com/jariq/Pkcs11Interop.PDF/issues">https://github.com/jariq/Pkcs11Interop.PDF/issues</a>
 * - Questions with pkcs11 tag on StackOverflow:<br/>
 * <a href="http://stackoverflow.com/questions/tagged/pkcs11">http://stackoverflow.com/questions/tagged/pkcs11</a>
 * - Commercial support from original developer:<br/>
 * <a href="mailto:info@pkcs11interop.net">info@pkcs11interop.net</a>
 * 
 * \section sec_about About
 * Pkcs11Interop.PDF has been written by <a href="http://www.jimrich.sk">Jaroslav Imrich</a> as a part of <a href="http://www.pkcs11interop.net">Pkcs11Interop</a> project. Commercial license and support are provided by Slovakia (EU) based company <a href="http://www.jwc.sk">JWC s.r.o.</a>
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
 * \example DemoApp.cs
 */
