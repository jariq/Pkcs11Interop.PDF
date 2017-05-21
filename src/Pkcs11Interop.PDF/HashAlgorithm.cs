/*
 *  Pkcs11Interop.PDF - Integration layer for Pkcs11Interop 
 *                      and iText (iTextSharp) libraries
 *  Copyright (c) 2013-2017 JWC s.r.o. <http://www.jwc.sk>
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

using System;

namespace Net.Pkcs11Interop.PDF
{
    /// <summary>
    /// Hash algorithm
    /// </summary>
    public enum HashAlgorithm
    {
        /// <summary>
        /// The SHA1 hash algorithm
        /// </summary>
        SHA1,

        /// <summary>
        /// The SHA256 hash algorithm
        /// </summary>
        SHA256,

        /// <summary>
        /// The SHA384 hash algorithm
        /// </summary>
        SHA384,

        /// <summary>
        /// The SHA512 hash algorithm
        /// </summary>
        SHA512
    }
}
