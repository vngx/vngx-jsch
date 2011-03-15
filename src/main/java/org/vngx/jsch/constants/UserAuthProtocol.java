/*
 * Copyright (c) 2010-2011 Michael Laudati, N1 Concepts LLC.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. The names of the authors may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL N1
 * CONCEPTS LLC OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.vngx.jsch.constants;

/**
 * <p>SSH message code constants for the SSH user authentication protocol.  The
 * Message Number is a byte value that describes the payload of a packet.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4251#section-7">RFC 4251 - The
 * Secure Shell (SSH) Protocol Architecture: Message Numbers</a></p>
 * <p><a href="http://tools.ietf.org/html/rfc4250">RFC 4250 - The Secure Shell
 * (SSH) Protocol Assigned Numbers</a></p>
 *
 * @author Michael Laudati
 */
public interface UserAuthProtocol {

	/** SSH message code constant '{@value}' for user auth request. */
	byte SSH_MSG_USERAUTH_REQUEST = 50;
	/** SSH message code constant '{@value}' for user auth failure. */
	byte SSH_MSG_USERAUTH_FAILURE = 51;
	/** SSH message code constant '{@value}' for user auth success. */
	byte SSH_MSG_USERAUTH_SUCCESS = 52;
	/** SSH message code constant '{@value}' for user auth banner. */
	byte SSH_MSG_USERAUTH_BANNER = 53;
	/** SSH message code constant '{@value}' for user auth info request. */
	byte SSH_MSG_USERAUTH_INFO_REQUEST = 60;
	/** SSH message code constant '{@value}' for user auth response. */
	byte SSH_MSG_USERAUTH_INFO_RESPONSE = 61;
	/** SSH message code constant '{@value}' to request a password change. */
	byte SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;
	/** SSH message code constant '{@value}' for user auth public key OK. */
	byte SSH_MSG_USERAUTH_PK_OK = 60;
	/** SSH message code constant '{@value}' for user auth GSS API response. */
	byte SSH_MSG_USERAUTH_GSSAPI_RESPONSE = 60;
	/** SSH message code constant '{@value}' for user auth GSS API token. */
	byte SSH_MSG_USERAUTH_GSSAPI_TOKEN = 61;
	/** SSH message code constant '{@value}' for user auth GSS API exchange complete. */
	byte SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE = 63;
	/** SSH message code constant '{@value}' for user auth GSS API error. */
	byte SSH_MSG_USERAUTH_GSSAPI_ERROR = 64;
	/** SSH message code constant '{@value}' for user auth GSS API error token. */
	byte SSH_MSG_USERAUTH_GSSAPI_ERRTOK = 65;
	/** SSH message code constant '{@value}' for user auth GSS API mic?. */
	byte SSH_MSG_USERAUTH_GSSAPI_MIC = 66;
	
}
