Preparing the testing environment
*********************************

1.  Create directory "c:\temp\" (or any other) that will be used as 
    an output directory for the tests.
2.  Import certificate from "John_Doe.p12" file to your PKCS#11 enabled 
    device (smartcard, HSM etc.). Password for the PKCS#12 file is "password".
3.  Edit variables in Net.Pkcs11Interop.PDF.Tests.Pkcs11ExplorerTest 
    class stored in Pkcs11ExplorerTest.cs file to suit your needs.
4.  Edit variables in Net.Pkcs11Interop.PDF.Tests.Pkcs11RsaSignatureExample 
    class stored in Pkcs11RsaSignatureExample.cs file to suit your needs.
5.  Edit properties in Net.Pkcs11Interop.PDF.Tests.Pkcs11RsaSignatureTest
    class stored in Pkcs11RsaSignatureTest.cs file to suit your needs.
6.  Rebuild and run the tests.

Converting NUnit test project to Visual Studio UnitTests
********************************************************

1.  Open "Pkcs11Interop.PDF.sln" solution in Visual Studio
2.  Add new "Test project" named "TestProject1" to the solution
3.  Delete automatically created file "UnitTest1.cs" from "TestProject1"
4.  Righ click "TestProject1" project and add reference 
    to "Pkcs11Interop.PDF" project, iTextSharp and Pkcs11Interop libraries
5.  Drag all files (excluding AssemblyInfo.cs) from "Pkcs11Interop.PDF.Tests" 
    project and drop them into "TestProject1"
6.  Right click "Pkcs11Interop.PDF.Tests" project and choose "Unload project" 
    to unload it from solution
7.  Mass replace (CTRL + SHIFT + H) in entire solution:
    using NUnit.Framework;
    to
    using Microsoft.VisualStudio.TestTools.UnitTesting;
8.  Mass replace (CTRL + SHIFT + H) in entire solution:
    [TestFixture()]
    to
    [TestClass]
9.  Mass replace (CTRL + SHIFT + H) in entire solution:
    [Test()]
    to
    [TestMethod]
10. Rebuild solution
