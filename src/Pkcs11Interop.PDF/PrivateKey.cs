/*
 *  Pkcs11Interop.PDF - Integration layer for Pkcs11Interop 
 *                      and iText (iTextSharp) libraries
 *  Copyright (c) 2013-2016 JWC s.r.o. <http://www.jwc.sk>
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

using Org.BouncyCastle.Crypto;
using System.Security.Cryptography.X509Certificates;
using BCX509 = Org.BouncyCastle.X509;

namespace Net.Pkcs11Interop.PDF
{
    /// <summary>
    /// Represents private key accessible via PKCS#11 interface
    /// </summary>
    public class PrivateKey
    {
        /// <summary>
        /// Hex encoded string with identifier (value of CKA_ID attribute) of the private key
        /// </summary>
        private string _id = null;

        /// <summary>
        /// Hex encoded string with identifier (value of CKA_ID attribute) of the private key
        /// </summary>
        public string Id
        {
            get
            {
                return _id;
            }
        }

        /// <summary>
        /// Label (value of CKA_LABEL attribute) of the private key
        /// </summary>
        private string _label = null;

        /// <summary>
        /// Label (value of CKA_LABEL attribute) of the private key
        /// </summary>
        public string Label
        {
            get
            {
                return _label;
            }
        }

        /// <summary>
        /// Public part of the key. May be null for unsupported key types.
        /// </summary>
        private AsymmetricKeyParameter _publicKey = null;

        /// <summary>
        /// Public part of the key. May be null for unsupported key types.
        /// </summary>
        public AsymmetricKeyParameter PublicKey
        {
            get
            {
                return _publicKey;
            }
        }

        /// <summary>
        /// Intitializes class instance
        /// </summary>
        /// <param name="id">Hex encoded string with identifier (value of CKA_ID attribute) of the private key</param>
        /// <param name="label">Label (value of CKA_LABEL attribute) of the private key</param>
        /// <param name="publicKey">Public part of the key or null for unsupported key types</param>
        internal PrivateKey(string id, string label, AsymmetricKeyParameter publicKey)
        {
            _id = id;
            _label = label;
            _publicKey = publicKey;
        }

        /// <summary>
        /// Checks whether specified certificate matches this private key
        /// </summary>
        /// <param name="certificate">Certificate to be checked</param>
        /// <returns>Null if match cannot be performed, true if certificate matches, false otherwise</returns>
        public bool? Matches(Certificate certificate)
        {
            if (certificate == null || certificate.PublicKey == null)
                return null;

            if (this.PublicKey == null)
                return null;

            return this.PublicKey.Equals(certificate.PublicKey);
        }

        /// <summary>
        /// Checks whether specified certificate matches this private key
        /// </summary>
        /// <param name="certificate">Certificate to be checked</param>
        /// <returns>Null if match cannot be performed, true if certificate matches, false otherwise</returns>
        public bool? Matches(BCX509.X509Certificate certificate)
        {
            if (certificate == null)
                return null;

            if (this.PublicKey == null)
                return null;

            return this.PublicKey.Equals(certificate.GetPublicKey());
        }

        /// <summary>
        /// Checks whether specified certificate matches this private key
        /// </summary>
        /// <param name="certificate">Certificate to be checked</param>
        /// <returns>Null if match cannot be performed, true if certificate matches, false otherwise</returns>
        public bool? Matches(X509Certificate2 certificate)
        {
            if (certificate == null)
                return null;

            return Matches(CertUtils.ToBouncyCastleObject(certificate));
        }
    }
}
