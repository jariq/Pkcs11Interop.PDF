using System.Reflection;
using System.Runtime.CompilerServices;

// Information about this assembly is defined by the following attributes. 
// Change them to the values specific to your project.

[assembly: AssemblyTitle("Pkcs11Interop.PDF")]
[assembly: AssemblyDescription("Integration layer for Pkcs11Interop and iText (iTextSharp) libraries")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("JWC s.r.o.")]
[assembly: AssemblyProduct("Pkcs11Interop.PDF")]
[assembly: AssemblyCopyright("Copyright (c) 2013 JWC s.r.o. All Rights Reserved.")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]

// The assembly version has the format "{Major}.{Minor}.{Build}.{Revision}".
// The form "{Major}.{Minor}.*" will automatically update the build and revision,
// and "{Major}.{Minor}.{Build}.*" will update just the revision.

[assembly: AssemblyVersion("1.0")]

// The following attributes are used to specify the signing key for the assembly, 
// if desired. See the Mono documentation for more information about signing.

//[assembly: AssemblyDelaySign(false)]
//[assembly: AssemblyKeyFile("")]

/*! \mainpage Integration layer for Pkcs11Interop and iText (iTextSharp) libraries
 *
 * <a class="el" href="http://sourceforge.net/projects/itextsharp/">iTextSharp</a> is a C# port of iText, an open-source Java library for PDF generation and manipulation. It can be used to create PDF documents from scratch, to convert XML to PDF, to fill out interactive PDF forms, to stamp new content on existing PDF documents, to split and merge existing PDF documents, to add digital signatures to PDF documents and much more.
 * 
 * <a class="el" href="http://www.pkcs11interop.net">Pkcs11interop</a> is an open-source project written in C# that brings full power of PKCS#11 API to .NET environment. PKCS#11 is cryptography standard published by RSA Laboratories that defines ANSI C API (called cryptoki) to access smart cards and other types of cryptographic hardware.
 *
 * <a class="el" href="https://github.com/jariq/Pkcs11Interop.PDF">Pkcs11interop.PDF</a> is also an open-source project written in C#. It creates an integration layer between Pkcs11Interop and iTextSharp libraries by extending iTextSharp with the ability to digitally sign PDF document with almost any PKCS#11 compatible device. Pkcs11interop.PDF is very easy to use. All you need to do is create an instance of Net.Pkcs11Interop.PDF.Pkcs11Signature class and pass it to iTextSharp that will take care of PDF signing. Please take a look at <a class="el" href="examples.html">our examples</a> for more details.
 *
 * If you are looking for a more general information about digital signatures in PDF documents I recommend you read a great white paper called &quot;<a class="el" href="http://itextpdf.com/book/digitalsignatures/">Digital Signatures for PDF documents</a>&quot; written by Bruno Lowagie from <a class="el" href="http://itextpdf.com/">iText Software</a>. There are also many useful code samples in <a class="el" href="http://svn.code.sf.net/p/itextsharp/code/tutorial">iTextSharp SVN repository</a>.
 * 
 * Please visit Pkcs11interop project website - <a class="el" href="http://www.pkcs11interop.net">pkcs11interop.net</a> - for more information regarding updates, licensing, support etc.
 */
