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
import org.vngx.jsch.Util;
import org.vngx.jsch.constants.MessageConstants;
import org.vngx.jsch.exception.JSchException;
import java.util.Set;

/**
 * Implementation of <code>UserAuth</code> for authenticating an SSH session
 * using a public key.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public final class UserAuthPublicKey extends UserAuth {

	@Override
	protected boolean authUser(Session session, byte[] password) throws Exception {
		super.authUser(session, password);

		byte[] passphrase = null;
		final Set<Identity> identities = IdentityManager.getManager().getIdentities();
		synchronized ( identities ) {
			if( identities.isEmpty() ) {
				return false;
			}

			identityLoop:
			for( Identity identity : identities ) {
				byte[] pubkeyblob = identity.getPublicKeyBlob();

				if( pubkeyblob != null ) {
					// send
					// byte      SSH_MSG_USERAUTH_REQUEST(50)
					// string    user name
					// string    service name ("ssh-connection")
					// string    "publickey"
					// boolen    FALSE
					// string    plaintext password (ISO-10646 UTF-8)
					_packet.reset();
					_buffer.putByte(SSH_MSG_USERAUTH_REQUEST);
					_buffer.putString(session.getUserName());
					_buffer.putString(SSH_CONNECTION);
					_buffer.putString(UserAuth.PUBLICKEY);
					_buffer.putByte((byte) 0);
					_buffer.putString(identity.getAlgorithmName());
					_buffer.putString(pubkeyblob);
					session.write(_packet);

					loop1:
					while( true ) {
						switch( session.read(_buffer).getCommand() & 0xff ) {
							case SSH_MSG_USERAUTH_BANNER:
								userAuthBanner();
								continue loop1;

							case SSH_MSG_USERAUTH_PK_OK:
								break loop1;
								
							case SSH_MSG_USERAUTH_FAILURE:
							default:
								continue identityLoop;
						}
					}
				}

				int count = 5;	// Make this configurable, 5 attempts to enter correct passphrase
				while( count-- > 0 ) {
					if( identity.isEncrypted() ) {
						if( _userinfo == null ) {
							throw new JSchException("UserAuth 'publickey' fail: identity is encrypted, no passphrase");
						} else if( !_userinfo.promptPassphrase(String.format(MessageConstants.PROMPT_PASSPHRASE, identity.getName())) ) {
							throw new AuthCancelException("UserAuth 'publickey' canceled by user");
						}
						if( _userinfo.getPassphrase() != null ) {
							passphrase = Util.str2byte(_userinfo.getPassphrase());
						}
					}

					if( (!identity.isEncrypted() || passphrase != null) && identity.setPassphrase(passphrase) ) {
						break;
					}
					Util.bzero(passphrase);
					passphrase = null;
				}
				Util.bzero(passphrase);
				passphrase = null;

				if( identity.isEncrypted() ) {
					continue;
				}
				if( pubkeyblob == null ) {
					pubkeyblob = identity.getPublicKeyBlob();
				}
				if( pubkeyblob == null ) {
					continue;
				}

				// send
				// byte      SSH_MSG_USERAUTH_REQUEST(50)
				// string    user name
				// string    service name ("ssh-connection")
				// string    "publickey"
				// boolen    TRUE
				// string    plaintext password (ISO-10646 UTF-8)
				_packet.reset();
				_buffer.setOffSet(0);
				_buffer.putByte(SSH_MSG_USERAUTH_REQUEST);
				_buffer.putString(session.getUserName());
				_buffer.putString(SSH_CONNECTION);
				_buffer.putString(UserAuth.PUBLICKEY);
				_buffer.putByte((byte) 1);
				_buffer.putString(identity.getAlgorithmName());
				_buffer.putString(pubkeyblob);

				byte[] sid = session.getSessionId();
				byte[] tmpData = new byte[4 + sid.length + _buffer.getLength() - 5];
				Buffer tmp = new Buffer(tmpData);
				tmp.putString(sid);
				tmp.putBytes(_buffer, 5, _buffer.getLength()-5);
				byte[] signature = identity.getSignature(tmpData);
				if( signature == null ) {  // for example, too long key length.
					break;
				}
				_buffer.putString(signature);
				session.write(_packet);

				loop2:
				while( true ) {
					switch( session.read(_buffer).getCommand() & 0xff ) {
						case SSH_MSG_USERAUTH_SUCCESS:
							return true;	// User successfully authed by publickey!

						case SSH_MSG_USERAUTH_BANNER:
							userAuthBanner();
							continue loop2;	// Display banner message and continue

						case SSH_MSG_USERAUTH_FAILURE:
							userAuthFailure();
							break loop2;	// Handle user auth failure and continue
					}
					break;
				}
			}
		}
		return false;
	}
	
}
