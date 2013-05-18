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

namespace Net.Pkcs11Interop.PDF
{
    /// <summary>
    /// Exception indicating that requested object was not found on the token
    /// </summary>
    public class ObjectNotFoundException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the ObjectNotFoundException class
        /// </summary>
        public ObjectNotFoundException()
            : base()
        {
            
        }
        
        /// <summary>
        /// Initializes a new instance of the ObjectNotFoundException class with a specified error message
        /// </summary>
        /// <param name="message">The message that describes the error</param>
        public ObjectNotFoundException(string message)
            : base(message)
        {
            
        }
        
        /// <summary>
        /// Initializes a new instance of the ObjectNotFoundException class with a specified error message and a reference to the inner exception that is the cause of this exception
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception</param>
        /// <param name="innerException">The exception that is the cause of the current exception, or a null reference if no inner exception is specified.</param>
        public ObjectNotFoundException(string message, Exception innerException)
            : base(message, innerException)
        {
            
        }
    }
}
