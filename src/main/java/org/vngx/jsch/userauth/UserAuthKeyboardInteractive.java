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

/**
 * Implementation of <code>UserAuth</code> for authenticating an SSH session
 * using an interactive keyboard instance.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public final class UserAuthKeyboardInteractive extends UserAuth {

	/** Password prompt to display to user to ask for password. */
	private String _passwordPrompt;

	@Override
	public boolean authUser(Session session, byte[] password) throws Exception {
		super.authUser(session, password);
		if( !(_userinfo instanceof UIKeyboardInteractive) ) {
			return false;	// Fail if no keyboard interactive interface available
		} else if (password == null) {
			password = _userinfo.getPassword().getBytes();
		}
		_passwordPrompt = createPasswordPrompt(session);

		boolean cancel = false;
		while( true ) {
			// send keyboard interactive user auth request
			// byte      SSH_MSG_USERAUTH_REQUEST(50)
			// string    user name (ISO-10646 UTF-8, as defined in [RFC-2279])
			// string    service name (US-ASCII) "ssh-userauth" ? "ssh-connection"
			// string    "keyboard-interactive" (US-ASCII)
			// string    language tag (as defined in [RFC-3066])
			// string    submethods (ISO-10646 UTF-8)
			_packet.reset();
			_buffer.putByte(SSH_MSG_USERAUTH_REQUEST);
			_buffer.putString(session.getUserName());
			_buffer.putString(SSH_CONNECTION);
			_buffer.putString(KEYBOARD_INTERACTIVE);
			_buffer.putString("");
			_buffer.putString("");
			session.write(_packet);

			boolean firstTime = true;
			loop:
			while( true ) {
				switch( session.read(_buffer).getCommand() & 0xff ) {
					case SSH_MSG_USERAUTH_SUCCESS:
						return true;	// User successfully authed with keyboard interactive

					case SSH_MSG_USERAUTH_BANNER:
						userAuthBanner();
						continue loop;	// Display banner message and continue

					case SSH_MSG_USERAUTH_FAILURE:
						userAuthFailure();
						if( firstTime ) {
							return false;
						}
						break loop;

					case SSH_MSG_USERAUTH_INFO_REQUEST:
						firstTime = false;
						_buffer.getInt();
						_buffer.getShort();
						String name = Util.byte2str(_buffer.getString());
						String instruction = Util.byte2str(_buffer.getString());
						_buffer.getString();	// Language tag
						int num = _buffer.getInt();
						String[] prompt = new String[num];
						boolean[] echo = new boolean[num];
						for( int i = 0; i < num; i++ ) {
							prompt[i] = Util.byte2str(_buffer.getString());
							echo[i] = _buffer.getByte() != 0;
						}

						byte[][] response = null;
						if( password != null && prompt.length == 1 && !echo[0] && prompt[0].toLowerCase().startsWith("password:") ) {
							response = new byte[][] { password };
							password = null;
						} else if( num > 0 || (name.length() > 0 || instruction.length() > 0) ) {
							UIKeyboardInteractive kbi = (UIKeyboardInteractive) _userinfo;
							String[] _response = kbi.promptKeyboardInteractive(_passwordPrompt, name, instruction, prompt, echo);
							if( _response != null ) {
								response = new byte[_response.length][];
								for( int i = 0; i < _response.length; i++ ) {
									response[i] = Util.str2byte(_response[i]);
								}
							}
						}

						// byte      SSH_MSG_USERAUTH_INFO_RESPONSE(61)
						// int       num-responses
						// string    response[1] (ISO-10646 UTF-8)
						// ...
						// string    response[num-responses] (ISO-10646 UTF-8)
						_packet.reset();
						_buffer.putByte(SSH_MSG_USERAUTH_INFO_RESPONSE);
						if( num > 0 && (response == null /* cancel */ ||  num != response.length) ) {
							if( response == null ) {
								// working around the bug in OpenSSH ;-<
								_buffer.putInt(num);
								for( int i = 0; i < num; i++ ) {
									_buffer.putString("");
								}
							} else {
								_buffer.putInt(0);
							}
							if( response == null ) {
								cancel = true;
							}
						} else {
							_buffer.putInt(num);
							for( int i = 0; i < num; i++ ) {
								_buffer.putString(response[i]);
								Util.bzero(response[i]);	// Zero password in response
							}
						}
						session.write(_packet);
						continue loop;
				}
				return false;
			}
			if( cancel ) {
				throw new AuthCancelException("UserAuth 'keyboard-interactive' canceled by user");
			}
		}
	}

}
