@setlocal

@rem Delete output directory
rmdir /S /Q nuget

@rem Create output directories
mkdir nuget\lib\net20 || goto :error
mkdir nuget\lib\net40 || goto :error
mkdir nuget\lib\net45 || goto :error

@rem Copy assemblies
copy net20\Pkcs11Interop.PDF.dll nuget\lib\net20 || goto :error
copy net20\Pkcs11Interop.PDF.xml nuget\lib\net20 || goto :error
copy net40\Pkcs11Interop.PDF.dll nuget\lib\net40 || goto :error
copy net40\Pkcs11Interop.PDF.xml nuget\lib\net40 || goto :error
copy net45\Pkcs11Interop.PDF.dll nuget\lib\net45 || goto :error
copy net45\Pkcs11Interop.PDF.xml nuget\lib\net45 || goto :error

@rem Copy license
copy ..\src\Pkcs11Interop.PDF\LICENSE.txt nuget || goto :error

@rem Create classic package
copy Pkcs11Interop.PDF.nuspec nuget || goto :error
nuget pack nuget\Pkcs11Interop.PDF.nuspec || goto :error

@echo *** CREATE NUGET SUCCESSFUL ***
@endlocal
@exit /b 0

:error
@echo *** CREATE NUGET FAILED ***
@endlocal
@exit /b 1
