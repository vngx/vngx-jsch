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
 * <p>SSH message code constants for the SSH Connection Protocol.  The
 * Message Number is a byte value that describes the payload of a packet.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4251#section-7">RFC 4251 - The
 * Secure Shell (SSH) Protocol Architecture: Message Numbers</a></p>
 * <p><a href="http://tools.ietf.org/html/rfc4250">RFC 4250 - The Secure Shell
 * (SSH) Protocol Assigned Numbers</a></p>
 *
 * @author Michael Laudati
 */
public interface ConnectionProtocol {

	/** SSH message code constant '{@value}' for global request. */
	byte SSH_MSG_GLOBAL_REQUEST = 80;
	/** SSH message code constant '{@value}' for request success. */
	byte SSH_MSG_REQUEST_SUCCESS = 81;
	/** SSH message code constant '{@value}' for request failure. */
	byte SSH_MSG_REQUEST_FAILURE = 82;
	/** SSH message code constant '{@value}' to signal channel open. */
	byte SSH_MSG_CHANNEL_OPEN = 90;
	/** SSH message code constant '{@value}' to signal channel open confirmation. */
	byte SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
	/** SSH message code constant '{@value}' to signal channel open failure. */
	byte SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
	/** SSH message code constant '{@value}' to signal channel window adjust. */
	byte SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
	/** SSH message code constant '{@value}' to signal channel data. */
	byte SSH_MSG_CHANNEL_DATA = 94;
	/** SSH message code constant '{@value}' to signal channel extended data. */
	byte SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
	/** SSH message code constant '{@value}' to signal channel end of file. */
	byte SSH_MSG_CHANNEL_EOF = 96;
	/** SSH message code constant '{@value}' to signal channel close. */
	byte SSH_MSG_CHANNEL_CLOSE = 97;
	/** SSH message code constant '{@value}' to signal channel request. */
	byte SSH_MSG_CHANNEL_REQUEST = 98;
	/** SSH message code constant '{@value}' to signal channel success. */
	byte SSH_MSG_CHANNEL_SUCCESS = 99;
	/** SSH message code constant '{@value}' to signal channel failure. */
	byte SSH_MSG_CHANNEL_FAILURE = 100;

	/*
	 * 4.3.  Channel Connection Failure Reason Codes and Descriptions
	 *
	 * The Channel Connection Failure 'reason code' is a uint32 value.  The
	 * associated Channel Connection Failure 'description' text is a human-
	 * readable message that describes the channel connection failure reason.
	 * This is described in [SSH-CONNECT].
	 *
	 * 4.3.1.  Conventions
	 *
	 * Protocol packets containing the SSH_MSG_CHANNEL_OPEN_FAILURE message MUST
	 * have Channel Connection Failure 'reason code' values in the range of
	 * 0x00000001 to 0xFFFFFFFF.
	 */
	/** 
	 * SSH channel connection failure reason code constant for open
	 * administratively prohibited code.
	 */
	int SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1;
	/**
	 * SSH channel connection failure reason code constant for open connection
	 * failed code.
	 */
	int SSH_OPEN_CONNECT_FAILED = 2;
	/**
	 * SSH channel connection failure reason code constant for open unknown
	 * channel type code.
	 */
	int SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3;
	/**
	 * SSH channel connection failure reason code constant for open resource
	 * shortage code.
	 */
	int SSH_OPEN_RESOURCE_SHORTAGE = 4;
	
}
