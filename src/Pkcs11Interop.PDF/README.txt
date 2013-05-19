Pkcs11Interop.PDF
Integration layer for Pkcs11Interop and iText (iTextSharp) libraries
********************************************************************

iTextSharp [0] is a C# port of iText, an open-source Java library for PDF 
generation and manipulation. It can be used to create PDF documents from 
scratch, to convert XML to PDF, to fill out interactive PDF forms, to stamp 
new content on existing PDF documents, to split and merge existing PDF 
documents, to add digital signatures to PDF documents and much more.

Pkcs11interop [1] is an open-source project written in C# that brings full 
power of PKCS#11 API to .NET environment. PKCS#11 is cryptography standard 
published by RSA Laboratories that defines ANSI C API (called cryptoki) 
to access smart cards and other types of cryptographic hardware.

Pkcs11interop.PDF is also an open-source project written in C#. It creates an 
integration layer between Pkcs11Interop and iTextSharp libraries by extending 
iTextSharp with the ability to digitally sign PDF document with almost any 
PKCS#11 compatible device. Pkcs11interop.PDF is very easy to use. All you need 
to do is create an instance of Net.Pkcs11Interop.PDF.Pkcs11Signature class 
and pass it to iTextSharp that will take care of PDF signing. Please take 
a look at our examples [3] for more details.

If you are looking for a more general information about digital signatures in 
PDF documents I recommend you read a great white paper called "Digital 
Signatures for PDF documents" [4] written by Bruno Lowagie from iText 
Software [5]. There are also many useful code samples in iTextSharp SVN 
repository [6].

Please visit Pkcs11interop project website [1] for more information regarding 
updates, licensing, support etc.

[0] http://sourceforge.net/projects/itextsharp/
[1] http://www.pkcs11interop.net
[2] https://github.com/jariq/Pkcs11Interop.PDF
[3] http://www.pkcs11interop.net/pdf/doc/examples.html
[4] http://itextpdf.com/book/digitalsignatures/
[5] http://itextpdf.com/
[6] http://svn.code.sf.net/p/itextsharp/code/tutorial
