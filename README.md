Pkcs11Interop.PDF
=================
**Integration layer for Pkcs11Interop and iText (iTextSharp) libraries**

## Table of Contents

* [Overview](#overview)
* [Documentation](#documentation)
* [Download](#download)
* [License](#license)
* [Support](#support)
* [Related projects](#related-projects)
* [About](#about)

## Overview

[iTextSharp](https://github.com/itext/itextsharp) is a C# port of iText - an open-source Java library for PDF generation and manipulation. It can be used to create PDF documents from scratch, to convert XML to PDF, to fill out interactive PDF forms, to stamp new content on existing PDF documents, to split and merge existing PDF documents, to add digital signatures to PDF documents and much more.

[Pkcs11interop](https://github.com/Pkcs11Interop/Pkcs11Interop) is managed library written in C# that brings full power of PKCS#11 API to the .NET environment. PKCS#11 is cryptography standard maintained by the OASIS PKCS 11 Technical Committee (originally published by RSA Laboratories) that defines ANSI C API to access smart cards and other types of cryptographic hardware.

[Pkcs11interop.PDF](https://github.com/jariq/Pkcs11Interop.PDF) creates an integration layer between Pkcs11Interop and iTextSharp libraries by extending iTextSharp with the ability to digitally sign PDF document with the private key stored on almost any PKCS#11 compatible device.

Pkcs11Interop.PDF library:
* enables iTextSharp to digitally sign PDF document with smartcard or any other PKCS#11 compatible device
* is compatible with .NET Framework and Mono
* is supported on Windows, Linux and Mac OS X
* is supported on both 32-bit and 64-bit platforms
* is available under open-source or commercial license
* uses 100% managed and fully documented code
* is directly supported by its original developer

## Documentation

Pkcs11Interop.PDF API is fully documented with the inline XML documentation that is displayed by the most of the modern IDEs during the application development. Detailed [Pkcs11Interop.PDF API documentation](https://www.pkcs11interop.net/extensions/pdf/) is also available online.

Pkcs11Interop.PDF source code contains well documented [unit tests](/src/Pkcs11Interop.PDF.Tests) and [demonstration command line application](src/Pkcs11Interop.PDF.Demo) that also serve as official code samples.

General information about digital signatures in PDF documents can be found in a great white paper called [Digital Signatures for PDF documents](http://pages.itextpdf.com/ebook-digital-signatures-for-pdf.html) written by Bruno Lowagie from [iText Software](http://itextpdf.com/).

There are also many useful code samples in [iTextSharp tutorial repository](https://github.com/itext/i5ns-tutorial).

## Download

Archives with the source code and binaries can be downloaded from [our releases page](https://github.com/jariq/Pkcs11Interop.PDF/releases).

[Official NuGet packages](https://www.nuget.org/packages/Pkcs11Interop.PDF/) are published in nuget.org repository.

All official items are signed with [GnuPG key or code-signing certificate of Jaroslav Imrich](https://www.jimrich.sk/crypto/).

## License

Pkcs11Interop.PDF uses dual-licensing model:
* **Licensing for open source projects:**  
  Pkcs11Interop.PDF is available under the terms of the [GNU Affero General Public License version 3](http://www.gnu.org/licenses/agpl-3.0.html) as published by the Free Software Foundation.
* **Licensing for other types of projects:**  
  Pkcs11Interop.PDF is available under the terms of flexible commercial license. Please contact JWC s.r.o. at [info@pkcs11interop.net](mailto:info@pkcs11interop.net) for more details.

## Support

Pick one of the options that best suits your needs:

* Public [issue tracker](https://github.com/jariq/Pkcs11Interop.PDF/issues) available at GitHub.com
* Questions with [pkcs11 tag](http://stackoverflow.com/questions/tagged/pkcs11) posted at StackOverflow.com
* Commercial support and consulting from the original developer available at [info@pkcs11interop.net](mailto:info@pkcs11interop.net)

## Related projects

* [Pkcs11Interop](https://www.pkcs11interop.net/)  
  Managed .NET wrapper for unmanaged PKCS#11 libraries.
* [Pkcs11Admin](https://www.pkcs11admin.net/)  
  GUI tool for administration of PKCS#11 enabled devices based on Pkcs11Interop library.
* [PKCS11-LOGGER](https://github.com/Pkcs11Interop/pkcs11-logger)  
  PKCS#11 logging proxy module useful for debugging of PKCS#11 enabled applications.
* [SoftHSM2-for-Windows](https://github.com/disig/SoftHSM2-for-Windows)  
  Pure software implementation of a cryptographic store accessible through a PKCS#11 interface.

## About

Pkcs11Interop.PDF has been written by [Jaroslav Imrich](http://www.jimrich.sk).  
Commercial license and support are provided by Slovakia (EU) based company [JWC s.r.o.](https://www.jwc.sk)