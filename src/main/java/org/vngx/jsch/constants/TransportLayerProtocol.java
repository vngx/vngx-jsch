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
 * <p>SSH message code constants for the SSH Transport Layer Protocol.  The
 * Message Number is a byte value that describes the payload of a packet.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4251#section-7">RFC 4251 - The
 * Secure Shell (SSH) Protocol Architecture: Message Numbers</a></p>
 * <p><a href="http://tools.ietf.org/html/rfc4250">RFC 4250 - The Secure Shell
 * (SSH) Protocol Assigned Numbers</a></p>
 *
 * @author Michael Laudati
 */
public interface TransportLayerProtocol {

	//=== Transport Layer Generic (1-19) ===
	/** SSH message code constant '{@value}' to signal SSH disconnect. */
	byte SSH_MSG_DISCONNECT = 1;
	/** SSH message code constant '{@value}' to signal ignore message. */
	byte SSH_MSG_IGNORE = 2;
	/** SSH message code constant '{@value}' to signal unimplemented. */
	byte SSH_MSG_UNIMPLEMENTED = 3;
	/** SSH message code constant '{@value}' to signal debug message. */
	byte SSH_MSG_DEBUG = 4;
	/** SSH message code constant '{@value}' to signal service request. */
	byte SSH_MSG_SERVICE_REQUEST = 5;
	/** SSH message code constant '{@value}' to signal SSH service accepted. */
	byte SSH_MSG_SERVICE_ACCEPT = 6;

	//=== Algorithm Negotiation Constants (20-29) ===
	/** SSH message code constant '{@value}' to signal key exchange init (client or server). */
	byte SSH_MSG_KEXINIT = 20;
	/** SSH message code constant '{@value}' to signal new keys (client or server). */
	byte SSH_MSG_NEWKEYS = 21;

	// === Key Exchange Message Constants (30-49) ===
	/** SSH message code constant '{@value}' to signal key exchange request. */
	byte SSH_MSG_KEXDH_INIT = 30;
	/** SSH message code constant '{@value}' to signal key exchange response. */
	byte SSH_MSG_KEXDH_REPLY = 31;
	/** SSH message code constant '{@value}' to signal key exchange DH group request. */
	byte SSH_MSG_KEX_DH_GEX_GROUP = 31;
	/** SSH message code constant '{@value}' to signal key exchange DH group init. */
	byte SSH_MSG_KEX_DH_GEX_INIT = 32;
	/** SSH message code constant '{@value}' to signal key exchange DH group reply. */
	byte SSH_MSG_KEX_DH_GEX_REPLY = 33;
	/** SSH message code constant '{@value}' to signal key exchange DH group request. */
	byte SSH_MSG_KEX_DH_GEX_REQUEST = 34;

	/*
	 * === SSH disconnect reason code constants ===
	 * 4.2.  Disconnection Messages Reason Codes and Descriptions
	 *
	 * The Disconnection Message 'reason code' is a uint32 value.  The
	 * associated Disconnection Message 'description' is a human-readable
	 * message that describes the disconnect reason.
	 *
	 * 4.2.1.  Conventions
	 *
	 * Protocol packets containing the SSH_MSG_DISCONNECT message MUST have
	 * Disconnection Message 'reason code' values in the range of 0x00000001
	 * to 0xFFFFFFFF.  These are described in [SSH-TRANS].
	 */
	/** SSH disconnect reason code constant for host not allowed to connect. */
	int SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1;
	/** SSH disconnect reason code constant for protocol error. */
	int SSH_DISCONNECT_PROTOCOL_ERROR = 2;
	/** SSH disconnect reason code constant for key exchange failure. */
	int SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3;
	/** SSH disconnect reason code constant for reserved errors. */
	int SSH_DISCONNECT_RESERVED = 4;
	/** SSH disconnect reason code constant for MAC errors. */
	int SSH_DISCONNECT_MAC_ERROR = 5;
	/** SSH disconnect reason code constant for compression errors. */
	int SSH_DISCONNECT_COMPRESSION_ERROR = 6;
	/** SSH disconnect reason code constant for service not available. */
	int SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7;
	/** SSH disconnect reason code constant for protocol version not supported. */
	int SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8;
	/** SSH disconnect reason code constant for host key not verifiable. */
	int SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9;
	/** SSH disconnect reason code constant for connection lost. */
	int SSH_DISCONNECT_CONNECTION_LOST = 10;
	/** SSH disconnect reason code constant for disconnect by application. */
	int SSH_DISCONNECT_BY_APPLICATION = 11;
	/** SSH disconnect reason code constant for too many connections. */
	int SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12;
	/** SSH disconnect reason code constant for user authentication canceled by user. */
	int SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13;
	/** SSH disconnect reason code constant for no more authentication methods available. */
	int SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;
	/** SSH disconnect reason code constant for illegal user name. */
	int SSH_DISCONNECT_ILLEGAL_USER_NAME = 15;

}
