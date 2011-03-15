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

import org.vngx.jsch.Session;
import org.vngx.jsch.UIKeyboardInteractive;
import org.vngx.jsch.Util;
import org.vngx.jsch.constants.MessageConstants;

/**
 * Implementation of <code>UserAuth</code> for authenticating an SSH session
 * using a password.
 * 
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public final class UserAuthPassword extends UserAuth {

	/** Prompt to display to user asking for password for username and host. */
	private String _passwordPrompt;

	@Override
	protected boolean authUser(Session session, byte[] password) throws Exception {
		super.authUser(session, password);

		// Generate pass prompt and retrieve password from session
		_passwordPrompt = createPasswordPrompt(session);

		try {
			int maxAttempts = 5;	// TODO Make this configurable
			while( maxAttempts-- > 0 ) {
				if( password == null ) {
					if( _userinfo == null ) {
						return false;	// Return if no way to prompt user for password
					} else if( !_userinfo.promptPassword(String.format(MessageConstants.PROMPT_PASSWORD, _passwordPrompt)) ) {
						throw new AuthCancelException("UserAuth 'password' canceled by user");
					} else if( _userinfo.getPassword() == null ) {
						throw new AuthCancelException("UserAuth 'password' canceled, password is null");
					}
					password = Util.str2byte(_userinfo.getPassword());
				}

				// send user auth password request
				// byte      SSH_MSG_USERAUTH_REQUEST(50)
				// string    user name
				// string    service name ("ssh-connection")
				// string    "password"
				// boolean   FALSE
				// string    plaintext password (ISO-10646 UTF-8)
				_packet.reset();
				_buffer.putByte(SSH_MSG_USERAUTH_REQUEST);
				_buffer.putString(session.getUserName());
				_buffer.putString(SSH_CONNECTION);
				_buffer.putString(UserAuth.PASSWORD);
				_buffer.putByte((byte) 0);
				_buffer.putString(password);
				session.write(_packet);

				loop:
				while( true ) {
					switch( session.read(_buffer).getCommand() & 0xff ) {
						case SSH_MSG_USERAUTH_SUCCESS:
							return true;	// User authenticated by password!

						case SSH_MSG_USERAUTH_BANNER:
							userAuthBanner();
							continue loop;	// Display banner and continue reading responses

						case SSH_MSG_USERAUTH_FAILURE:
							userAuthFailure();
							break loop;		// Process auth failure and continue

						case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
							if( !userAuthPasswordChangeRequest(session, password) ) {
								return false;	// User failed to change password
							}
							continue loop;	// Process change password request

						default:
							return false;	// Unknown response, fail 'password' method
					}
				}
				Util.bzero(password);	// Clear password after each attempt to
				password = null;		// allow re-prompt to user asking for password
			}
			return false;	// Reached maximum attempts for password, return...
		} finally {
			Util.bzero(password);
			password = null;
		}
	}

	/**
	 * Handles request to change user's password.
	 *
	 * @param session
	 * @param password
	 * @return true if successful, false if attempt failed
	 * @throws Exception if any errors occur
	 */
	private boolean userAuthPasswordChangeRequest(Session session, byte[] password) throws Exception {
		_buffer.getInt();
		_buffer.getShort();
		byte[] instruction = _buffer.getString();
		_buffer.getString();	// Language tag
		if( !(_userinfo instanceof UIKeyboardInteractive) ) {
			if( _userinfo != null ) {
				_userinfo.showMessage(MessageConstants.PASSWORD_MUST_CHANGE);
			}
			return false;	// Can't change password without keyboard-interactive
		}

		UIKeyboardInteractive kbi = (UIKeyboardInteractive) _userinfo;
		String[] response = kbi.promptKeyboardInteractive(
				_passwordPrompt, "Password Change Required", Util.byte2str(instruction),
				new String[]{"New Password: "}, new boolean[]{false});
		if( response == null ) {
			throw new AuthCancelException("UserAuth 'password' canceled by user during change request");
		}

		// send the change password request with old and new passwords
		// byte      SSH_MSG_USERAUTH_REQUEST(50)
		// string    user name
		// string    service name ("ssh-connection")
		// string    "password"
		// boolean   TRUE
		// string    plaintext old password (ISO-10646 UTF-8)
		// string    plaintext new password (ISO-10646 UTF-8)
		_packet.reset();
		_buffer.putByte(SSH_MSG_USERAUTH_REQUEST);
		_buffer.putString(session.getUserName());
		_buffer.putString(SSH_CONNECTION);
		_buffer.putString(UserAuth.PASSWORD);
		_buffer.putByte((byte) 1);
		_buffer.putString(password);	// Original password

		byte[] newpassword = Util.str2byte(response[0]);
		_buffer.putString(newpassword);
		Util.bzero(newpassword);

		session.write(_packet);
		return true;
	}

}
