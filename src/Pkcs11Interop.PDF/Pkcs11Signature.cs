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
using iTextSharp.text.pdf.security;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Common;
using System.Security.Cryptography.X509Certificates;

namespace Net.Pkcs11Interop.PDF
{
    /*!
     * \example Pkcs11SignatureTest.cs
     */

    /// <summary>
    /// PKCS#11 signature creator
    /// </summary>
    public class Pkcs11Signature : IExternalSignature, IDisposable
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        protected bool _disposed = false;

        /// <summary>
        /// High level PKCS#11 wrapper
        /// </summary>
        protected Pkcs11 _pkcs11 = null;

        /// <summary>
        /// Logical reader with token used for signing
        /// </summary>
        protected Slot _slot = null;

        /// <summary>
        /// Master session where user is logged in
        /// </summary>
        protected Session _session = null;

        /// <summary>
        /// Handle of private key used for signing 
        /// </summary>
        protected ObjectHandle _privateKeyHandle = null;

        /// <summary>
        /// Label (value of CKA_LABEL attribute) of the private key used for signing
        /// </summary>
        protected string _ckaLabel = null;

        /// <summary>
        /// Identifier (value of CKA_ID attribute) of the private key used for signing
        /// </summary>
        protected byte[] _ckaId = null;

        /// <summary>
        /// Hash algorihtm used for the signature creation
        /// </summary>
        protected HashAlgorithm _hashAlgorihtm = HashAlgorithm.SHA512;

        /// <summary>
        /// Handle of certificate related to private key used for signing 
        /// </summary>
        protected ObjectHandle _certificateHandle = null;

        /// <summary>
        /// Raw data of certificate related to private key used for signing
        /// </summary>
        protected byte[] _certificateData = null;

        /// <summary>
        /// Initializes a new instance of the Pkcs11Signature class
        /// </summary>
        /// <param name="libraryPath">Path to the unmanaged PCKS#11 library</param>
        /// <param name="tokenSerial">Serial number of the token (smartcard) that contains signing key. May be null if tokenLabel is specified.</param>
        /// <param name="tokenLabel">Label of of the token (smartcard) that contains signing key. May be null if tokenSerial is specified.</param>
        /// <param name="pin">PIN for the token (smartcard)</param>
        /// <param name="ckaLabel">Label (value of CKA_LABEL attribute) of the private key used for signing. May be null if ckaId is specified.</param>
        /// <param name="ckaId">Hex encoded string with identifier (value of CKA_ID attribute) of the private key used for signing. May be null if ckaLabel is specified.</param>
        /// <param name="hashAlgorihtm">Hash algorihtm used for the signature creation</param>
        public Pkcs11Signature(string libraryPath, string tokenSerial, string tokenLabel, string pin, string ckaLabel, string ckaId, HashAlgorithm hashAlgorihtm)
        {
            byte[] pinValue = (pin == null) ? null : ConvertUtils.Utf8StringToBytes(pin);
            byte[] ckaIdValue = (ckaId == null) ? null : ConvertUtils.HexStringToBytes(ckaId);
            InitializePkcs11Signature(libraryPath, tokenSerial, tokenLabel, pinValue, ckaLabel, ckaIdValue, hashAlgorihtm);
        }

        /// <summary>
        /// Initializes a new instance of the Pkcs11Signature class
        /// </summary>
        /// <param name="libraryPath">Path to the unmanaged PCKS#11 library</param>
        /// <param name="tokenSerial">Serial number of the token (smartcard) that contains signing key. May be null if tokenLabel is specified.</param>
        /// <param name="tokenLabel">Label of of the token (smartcard) that contains signing key. May be null if tokenSerial is specified.</param>
        /// <param name="pin">PIN for the token (smartcard)</param>
        /// <param name="ckaLabel">Label (value of CKA_LABEL attribute) of the private key used for signing. May be null if ckaId is specified.</param>
        /// <param name="ckaId">Identifier (value of CKA_ID attribute) of the private key used for signing. May be null if ckaLabel is specified.</param>
        /// <param name="hashAlgorihtm">Hash algorihtm used for the signature creation</param>
        public Pkcs11Signature(string libraryPath, string tokenSerial, string tokenLabel, byte[] pin, string ckaLabel, byte[] ckaId, HashAlgorithm hashAlgorihtm)
        {
            InitializePkcs11Signature(libraryPath, tokenSerial, tokenLabel, pin, ckaLabel, ckaId, hashAlgorihtm);
        }

        /// <summary>
        /// Initializes a new instance of the Pkcs11Signature class
        /// </summary>
        /// <param name="libraryPath">Path to the unmanaged PCKS#11 library</param>
        /// <param name="tokenSerial">Serial number of the token (smartcard) that contains signing key. May be null if tokenLabel is specified.</param>
        /// <param name="tokenLabel">Label of of the token (smartcard) that contains signing key. May be null if tokenSerial is specified.</param>
        /// <param name="pin">PIN for the token (smartcard)</param>
        /// <param name="ckaLabel">Label (value of CKA_LABEL attribute) of the private key used for signing. May be null if ckaId is specified.</param>
        /// <param name="ckaId">Identifier (value of CKA_ID attribute) of the private key used for signing. May be null if ckaLabel is specified.</param>
        /// <param name="hashAlgorihtm">Hash algorihtm used for the signature creation</param>
        private void InitializePkcs11Signature(string libraryPath, string tokenSerial, string tokenLabel, byte[] pin, string ckaLabel, byte[] ckaId, HashAlgorithm hashAlgorihtm)
        {
            _pkcs11 = new Pkcs11(libraryPath, true);
            _slot = FindSlot(tokenSerial, tokenLabel);
            if (_slot == null)
                throw new TokenNotFoundException(string.Format("Token with serial \"{0}\" and label \"{1}\" was not found", tokenSerial, tokenLabel));
            
            _session = _slot.OpenSession(true);
            _session.Login(CKU.CKU_USER, pin);
            
            _privateKeyHandle = FindPrivateKey(ckaLabel, ckaId);
            if (_privateKeyHandle == null)
                throw new ObjectNotFoundException(string.Format("Private key with label \"{0}\" and id \"{1}\" was not found", ckaLabel, ConvertUtils.BytesToHexString(ckaId)));
            
            _ckaLabel = ckaLabel;
            _ckaId = ckaId;
            _hashAlgorihtm = hashAlgorihtm;
        }

        /// <summary>
        /// Gets the raw data of certificate related to private key used for signing
        /// </summary>
        /// <returns>Raw data of certificate related to private key used for signing</returns>
        public byte[] GetCertificateAsByteArray()
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            return GetCertificateContent();
        }

        /// <summary>
        /// Gets the certificate related to private key used for signing as Org.BouncyCastle.X509.X509Certificate
        /// </summary>
        /// <returns>Certificate related to private key used for signing as Org.BouncyCastle.X509.X509Certificate</returns>
        public Org.BouncyCastle.X509.X509Certificate GetCertificateAsX509Certificate()
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            Org.BouncyCastle.X509.X509CertificateParser x509CertificateParser = new Org.BouncyCastle.X509.X509CertificateParser();
            return x509CertificateParser.ReadCertificate(GetCertificateContent());
        }

        /// <summary>
        /// Gets the certificate related to private key used for signing as System.Security.Cryptography.X509Certificates.X509Certificate2
        /// </summary>
        /// <returns>Certificate related to private key used for signing as System.Security.Cryptography.X509Certificates.X509Certificate2</returns>
        public X509Certificate2 GetCertificateAsX509Certificate2()
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            return new X509Certificate2(GetCertificateContent());
        }

        /// <summary>
        /// Finds slot containing the token that matches specified criteria
        /// </summary>
        /// <param name="tokenSerial">Serial number of token that should be found</param>
        /// <param name="tokenLabel">Label of token that should be found</param>
        /// <returns>Slot containing the token that matches specified criteria</returns>
        private Slot FindSlot(string tokenSerial, string tokenLabel)
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            if (string.IsNullOrEmpty(tokenSerial) && string.IsNullOrEmpty(tokenLabel))
                throw new ArgumentException("Token serial and/or label has to be specified");

            List<Slot> slots = _pkcs11.GetSlotList(true);
            foreach (Slot slot in slots)
            {
                TokenInfo tokenInfo = slot.GetTokenInfo();

                if (!string.IsNullOrEmpty(tokenSerial))
                    if (0 != String.Compare(tokenSerial, tokenInfo.SerialNumber, StringComparison.InvariantCultureIgnoreCase))
                        continue;

                if (!string.IsNullOrEmpty(tokenLabel))
                    if (0 != String.Compare(tokenLabel, tokenInfo.Label, StringComparison.InvariantCultureIgnoreCase))
                        continue;

                return slot;
            }

            return null;
        }

        /// <summary>
        /// Finds private key that matches specified criteria
        /// </summary>
        /// <param name="ckaLabel">Label (value of CKA_LABEL attribute) of the private key</param>
        /// <param name="ckaId">Identifier (value of CKA_ID attribute) of the private key</param>
        /// <returns>Handle of private key that matches specified criteria</returns>
        private ObjectHandle FindPrivateKey(string ckaLabel, byte[] ckaId)
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            using (Session session = _slot.OpenSession(true))
            {
                List<ObjectAttribute> searchTemplate = new List<ObjectAttribute>();
                searchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, (uint) CKO.CKO_PRIVATE_KEY));
                searchTemplate.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) CKK.CKK_RSA));
                if (!string.IsNullOrEmpty(ckaLabel))
                    searchTemplate.Add(new ObjectAttribute(CKA.CKA_LABEL, ckaLabel));
                if (ckaId != null)
                    searchTemplate.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));

                List<ObjectHandle> foundObjects = _session.FindAllObjects(searchTemplate);
                if (foundObjects.Count != 1)
                    return null;
                
                return foundObjects[0];
            }
        }

        /// <summary>
        /// Finds certificate that matches specified criteria
        /// </summary>
        /// <param name="ckaLabel">Label (value of CKA_LABEL attribute) of the certificate</param>
        /// <param name="ckaId">Identifier (value of CKA_ID attribute) of the certificate</param>
        /// <returns>Handle of certificate that matches specified criteria</returns>
        private ObjectHandle FindCertificate(string ckaLabel, byte[] ckaId)
        { 
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            using (Session session = _slot.OpenSession(true))
            {
                List<ObjectAttribute> searchTemplate = new List<ObjectAttribute>();
                searchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, (uint) CKO.CKO_CERTIFICATE));
                searchTemplate.Add(new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, (uint) CKC.CKC_X_509));
                if (!string.IsNullOrEmpty(ckaLabel))
                    searchTemplate.Add(new ObjectAttribute(CKA.CKA_LABEL, ckaLabel));
                if (ckaId != null)
                    searchTemplate.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
                
                List<ObjectHandle> foundObjects = _session.FindAllObjects(searchTemplate);
                if (foundObjects.Count != 1)
                    return null;
                
                return foundObjects[0];
            }
        }

        /// <summary>
        /// Gets the raw data (value of CKA_VALUE attribute) of certificate related to private key used for signing
        /// </summary>
        /// <returns>Raw data of certificate related to private key used for signing</returns>
        private byte[] GetCertificateContent()
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            // Don't look for certificate if it was already found
            if (_certificateHandle == null)
            {
                _certificateHandle = FindCertificate(_ckaLabel, _ckaId);
                if (_certificateHandle == null)
                    throw new ObjectNotFoundException(string.Format("Certificate with label \"{0}\" and id \"{1}\" was not found", _ckaLabel, ConvertUtils.BytesToHexString(_ckaId)));
            }

            // Don't read certificate from token if it was already read
            if (_certificateData == null)
            {
                using (Session session = _slot.OpenSession(true))
                {
                    List<CKA> attributes = new List<CKA>();
                    attributes.Add(CKA.CKA_VALUE);
                    
                    List<ObjectAttribute> certificateAttributes = _session.GetAttributeValue(_certificateHandle, attributes);
                    _certificateData = certificateAttributes[0].GetValueAsByteArray();
                }
            }

            return _certificateData;
        }

        #region IExternalSignature

        /// <summary>
        /// Returns the hash algorithm
        /// </summary>
        /// <returns>The hash algorithm (e.g. "SHA1", "SHA256, ...")</returns>
        public string GetHashAlgorithm()
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);
            
            return _hashAlgorihtm.ToString();
        }

        /// <summary>
        /// Returns the encryption algorithm used for signing
        /// </summary>
        /// <returns>The encryption algorithm ("RSA" or "DSA")</returns>
        public string GetEncryptionAlgorithm()
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);
            
            return "RSA";
        }

        /// <summary>
        /// Signs the specified message using the encryption algorithm in combination with the digest algorithm
        /// </summary>
        /// <param name="message">the message you want to be hashed and signed</param>
        /// <returns>A signed message digest</returns>
        public byte[] Sign(byte[] message)
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            Mechanism mechanism = null;
            switch (_hashAlgorihtm)
            {
                case HashAlgorithm.SHA1:
                    mechanism = new Mechanism(CKM.CKM_SHA1_RSA_PKCS);
                    break;
                case HashAlgorithm.SHA256:
                    mechanism = new Mechanism(CKM.CKM_SHA256_RSA_PKCS);
                    break;
                case HashAlgorithm.SHA384:
                    mechanism = new Mechanism(CKM.CKM_SHA384_RSA_PKCS);
                    break;
                case HashAlgorithm.SHA512:
                    mechanism = new Mechanism(CKM.CKM_SHA512_RSA_PKCS);
                    break;
            }

            using (Session session = _slot.OpenSession(true))
                return session.Sign(mechanism, _privateKeyHandle, message);
        }

        #endregion

        #region IDisposable

        /// <summary>
        /// Disposes object
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        
        /// <summary>
        /// Disposes object
        /// </summary>
        /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!this._disposed)
            {
                // Dispose managed objects
                if (disposing)
                {
                    _certificateData = null;
                    _certificateHandle = null;
                    _hashAlgorihtm = HashAlgorithm.SHA512;
                    _ckaId = null;
                    _ckaLabel = null;
                    _privateKeyHandle = null;

                    if (_session != null)
                    {
                        _session.Logout();
                        _session.CloseSession();
                        _session.Dispose();
                        _session = null;
                    }
                    
                    _slot = null;
                    
                    if (_pkcs11 != null)
                    {
                        _pkcs11.Dispose();
                        _pkcs11 = null;
                    }
                }
                
                // Dispose unmanaged objects

                _disposed = true;
            }
        }
        
        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~Pkcs11Signature()
        {
            Dispose(false);
        }

        #endregion
    }
}

