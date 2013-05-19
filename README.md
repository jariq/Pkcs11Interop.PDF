Pkcs11Interop.PDF
=================
Integration layer for Pkcs11Interop and iText (iTextSharp) libraries
--------------------------------------------------------------------

[iTextSharp](http://sourceforge.net/projects/itextsharp/) is a C# port of iText, an open-source Java library for PDF generation and manipulation. It can be used to create PDF documents from scratch, to convert XML to PDF, to fill out interactive PDF forms, to stamp new content on existing PDF documents, to split and merge existing PDF documents, to add digital signatures to PDF documents and much more.

[Pkcs11interop](http://www.pkcs11interop.net) is an open-source project written in C# that brings full power of PKCS#11 API to .NET environment. PKCS#11 is cryptography standard published by RSA Laboratories that defines ANSI C API (called cryptoki) to access smart cards and other types of cryptographic hardware.

[Pkcs11interop.PDF](https://github.com/jariq/Pkcs11Interop.PDF) is also an open-source project written in C#. It creates an integration layer between Pkcs11Interop and iTextSharp libraries by extending iTextSharp with the ability to digitally sign PDF document with almost any PKCS#11 compatible device. Pkcs11interop.PDF is very easy to use. All you need to do is create an instance of Net.Pkcs11Interop.PDF.Pkcs11Signature class and pass it to iTextSharp that will take care of PDF signing. Please take a look at [our examples](http://www.pkcs11interop.net/pdf/doc/examples.html) for more details.

If you are looking for a more general information about digital signatures in PDF documents I recommend you read a great white paper called "[Digital Signatures for PDF documents](http://itextpdf.com/book/digitalsignatures/)" written by Bruno Lowagie from [iText Software](http://itextpdf.com/). There are also many useful code samples in [iTextSharp SVN repository](http://svn.code.sf.net/p/itextsharp/code/tutorial).

Please visit Pkcs11interop project website - [pkcs11interop.net](http://www.pkcs11interop.net) - for more information regarding updates, licensing, support etc.
