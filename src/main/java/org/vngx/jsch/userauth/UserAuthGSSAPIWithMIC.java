/*
 * Copyright (c) 2002-2010 Atsuhiko Yamanaka, JCraft,Inc.  All rights reserved.
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
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
 * INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.vngx.jsch.userauth;

import org.vngx.jsch.Buffer;
import org.vngx.jsch.Session;
import org.vngx.jsch.exception.JSchException;
import java.util.Arrays;

/**
 * Implementation of <code>UserAuth</code> for authenticating an SSH session
 * using GSS-API.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public final class UserAuthGSSAPIWithMIC extends UserAuth {

	/** List of support OID strings as byte arrays. */
	private static final byte[][] SUPPORTED_OID = {
		// OID 1.2.840.113554.1.2.2 in DER
		{(byte) 0x6, (byte) 0x9, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
		(byte) 0x86, (byte) 0xf7, (byte) 0x12, (byte) 0x1, (byte) 0x2,
		(byte) 0x2}
	};
	/** Supported method String constant. */
	private static final String[] SUPPORTED_METHOD = {
		"gssapi-with-mic.krb5"
	};


	@Override
	protected boolean authUser(Session session, byte[] password) throws Exception {
		super.authUser(session, password);

		// byte            SSH_MSG_USERAUTH_REQUEST(50)
		// string          user name(in ISO-10646 UTF-8 encoding)
		// string          service name(in US-ASCII)
		// string          "gssapi"(US-ASCII)
		// uint32          n, the number of OIDs client supports
		// string[n]       mechanism OIDS
		_packet.reset();
		_buffer.putByte(SSH_MSG_USERAUTH_REQUEST);
		_buffer.putString(session.getUserName());
		_buffer.putString(SSH_CONNECTION);
		_buffer.putString(UserAuth.GSSAPI_WITH_MIC);
		_buffer.putInt(SUPPORTED_OID.length);
		for( byte[] supportedOID : SUPPORTED_OID ) {
			_buffer.putString(supportedOID);
		}
		session.write(_packet);

		String method = null;
		int command;
		while( true ) {
			command = session.read(_buffer).getCommand() & 0xff;

			if( command == SSH_MSG_USERAUTH_FAILURE ) {
				return false;
			} else if( command == SSH_MSG_USERAUTH_GSSAPI_RESPONSE ) {
				_buffer.getInt();
				_buffer.getShort();
				byte[] message = _buffer.getString();
				for( int i = 0; i < SUPPORTED_OID.length; i++ ) {
					if( Arrays.equals(message, SUPPORTED_OID[i]) ) {
						method = SUPPORTED_METHOD[i];
						break;
					}
				}
				if( method == null ) {
					return false;
				}
				break; // success
			} else if( command == SSH_MSG_USERAUTH_BANNER ) {
				userAuthBanner();
				continue;
			}
			return false;
		}

		GSSContext context;
		try {
			context = session.getConfig().getClassImpl(method);
		} catch(Exception e) {
			// TODO Error handling?
			return false;
		}

		try {
			context.create(session.getUserName(), session.getHost());
		} catch(JSchException e) {
			// TODO Error handling?
			return false;
		}

		byte[] token = new byte[0];
		while( !context.isEstablished() ) {
			try {
				token = context.init(token, 0, token.length);
			} catch(JSchException e) {
				// TODO
				// ERRTOK should be sent?
				// byte        SSH_MSG_USERAUTH_GSSAPI_ERRTOK
				// string      error token
				return false;
			}

			if( token != null ) {
				_packet.reset();
				_buffer.putByte(SSH_MSG_USERAUTH_GSSAPI_TOKEN);
				_buffer.putString(token);
				session.write(_packet);
			}

			if( !context.isEstablished() ) {
				command = session.read(_buffer).getCommand() & 0xff;
				if( command == SSH_MSG_USERAUTH_GSSAPI_ERROR ) {
					// uint32    major_status
					// uint32    minor_status
					// string    message
					// string    language tag
					command = session.read(_buffer).getCommand() & 0xff;
					//return false;
				} else if( command == SSH_MSG_USERAUTH_GSSAPI_ERRTOK ) {
					// string error token
					command = session.read(_buffer).getCommand() & 0xff;
					//return false;
				}
				if( command == SSH_MSG_USERAUTH_FAILURE ) {
					return false;
				}
				_buffer.getInt();
				_buffer.getShort();
				token = _buffer.getString();
			}
		}

		byte[] data = new byte[1024 * 20];
		Buffer mbuf = new Buffer(data);
		// string    session identifier
		// byte      SSH_MSG_USERAUTH_REQUEST
		// string    user name
		// string    service
		// string    "gssapi-with-mic"
		mbuf.putString(session.getSessionId());
		mbuf.putByte(SSH_MSG_USERAUTH_REQUEST);
		mbuf.putString(session.getUserName());
		mbuf.putString(SSH_CONNECTION);
		mbuf.putString(UserAuth.GSSAPI_WITH_MIC);

		byte[] mic = context.getMIC(data, 0, mbuf.getLength());
		if( mic == null ) {
			return false;
		}

		_packet.reset();
		_buffer.putByte(SSH_MSG_USERAUTH_GSSAPI_MIC);
		_buffer.putString(mic);
		session.write(_packet);

		context.dispose();

		command = session.read(_buffer).getCommand() & 0xff;

		if( command == SSH_MSG_USERAUTH_SUCCESS ) {
			return true;
		} else if( command == SSH_MSG_USERAUTH_FAILURE ) {
			userAuthFailure();
		}
		return false;
	}
	
}
