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

import static org.vngx.jsch.constants.TransportLayerProtocol.*;

import org.vngx.jsch.Buffer;
import org.vngx.jsch.JSch;
import org.vngx.jsch.Packet;
import org.vngx.jsch.Session;
import org.vngx.jsch.UserInfo;
import org.vngx.jsch.Util;
import org.vngx.jsch.config.SessionConfig;
import org.vngx.jsch.algorithm.Algorithms;
import org.vngx.jsch.constants.SSHConstants;
import org.vngx.jsch.constants.UserAuthProtocol;
import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.util.Logger.Level;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;

/**
 * Base implementation of <code>UserAuth</code> which performs the user
 * authorization for a given SSH session.  Implementations can define how the
 * user should be authorized for the session.  This class is part of the public
 * JSch API to allow developers to provide other mechanisms for user auth.
 *
 * The server drives the authentication by telling the client which
 * authentication methods can be used to continue the exchange at any given
 * time.  The client has the freedom to try the methods listed by the server in
 * any order.  This gives the server complete control over the authentication
 * process if desired, but also gives enough flexibility for the client to use
 * the methods it supports or that are most convenient for the user, when
 * multiple methods are offered by the server.
 *
 * Authentication methods are identified by their name.  The "none" method is
 * reserved, and MUST NOT be listed as supported.  However, it MAY be sent by
 * the client.  The server MUST always reject this request, unless the client is
 * to be granted access without any authentication, in which case, the server
 * MUST accept this request.  The main purpose of sending this request is to get
 * the list of supported methods from the server.
 *
 * The server SHOULD have a timeout for authentication and disconnect if the
 * authentication has not been accepted within the timeout period. The
 * RECOMMENDED timeout period is 10 minutes.  Additionally, the implementation
 * SHOULD limit the number of failed authentication attempts a client may
 * perform in a single session (the RECOMMENDED limit is 20 attempts).  If the
 * threshold is exceeded, the server SHOULD disconnect.
 *
 * All authentication requests MUST use the following message format.  Only the
 * first few fields are defined; the remaining fields depend on the
 * authentication method.
 *
 *		byte      SSH_MSG_USERAUTH_REQUEST
 *		string    user name in ISO-10646 UTF-8 encoding [RFC3629]
 *		string    service name in US-ASCII
 *		string    method name in US-ASCII
 *		....      method specific fields
 *
 * The 'user name' and 'service name' are repeated in every new authentication
 * attempt, and MAY change.  The server implementation MUST carefully check them
 * in every message, and MUST flush any accumulated authentication states if
 * they change.  If it is unable to flush an authentication state, it MUST
 * disconnect if the 'user name' or 'service name' changes.
 *
 * The 'service name' specifies the service to start after authentication. There
 * may be several different authenticated services provided.  If the requested
 * service is not available, the server MAY disconnect immediately or at any
 * later time.  Sending a proper disconnect message is RECOMMENDED. In any case,
 * if the service does not exist, authentication MUST NOT be accepted.
 *
 * If the requested 'user name' does not exist, the server MAY disconnect, or
 * MAY send a bogus list of acceptable authentication 'method name' values, but
 * never accept any.  This makes it possible for the server to avoid disclosing
 * information on which accounts exist.  In any case, if the 'user name' does
 * not exist, the authentication request MUST NOT be accepted.
 *
 * While there is usually little point for clients to send requests that the
 * server does not list as acceptable, sending such requests is not an error,
 * and the server SHOULD simply reject requests that it does not recognize.
 *
 * An authentication request MAY result in a further exchange of messages.  All
 * such messages depend on the authentication 'method name' used, and the client
 * MAY at any time continue with a new SSH_MSG_USERAUTH_REQUEST message, in
 * which case the server MUST abandon the previous authentication attempt and
 * continue with the new one.
 *
 * The following 'method name' values are defined.
 *		"publickey"             REQUIRED
 *		"password"              OPTIONAL
 *		"hostbased"             OPTIONAL
 *		"none"                  NOT RECOMMENDED
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public abstract class UserAuth implements UserAuthProtocol {

	/** SSH constant name for "none" user auth method. */
	public static final String NONE = "none";
	/** SSH constant name for "password" user auth method. */
	public static final String PASSWORD = "password";
	/** SSH constant name for "publickey" user auth method. */
	public static final String PUBLICKEY = "publickey";
	/** SSH constant name for "keyboard-interactive" user auth method. */
	public static final String KEYBOARD_INTERACTIVE = "keyboard-interactive";
	/** SSH constant name for "gssapi-with-mic" user auth method. */
	public static final String GSSAPI_WITH_MIC = "gssapi-with-mic";

	/** SSH constant message name for "ssh-userauth". */
	protected static final String SSH_USERAUTH = "ssh-userauth";
	/** SSH constant message name for "ssh-connection". */
	protected static final String SSH_CONNECTION = "ssh-connection";

	/* Each instance of UserAuth should have it's own, unshared buffer/packet
	 * to prevent leakage of passwords/passphrases, etc.  If a buffer instances
	 * are shared, it might not be cleared allowing next instance to see
	 * confidential data.
	 */
	/** Buffer from session for sending user auth requests. */
	protected final Buffer _buffer = new Buffer();
	/** Packet from session for sending user auth requests. */
	protected final Packet _packet = new Packet(_buffer);
	/** Interface for UI for user. */
	protected UserInfo _userinfo;
	

	/**
	 * Performs the user authentication as defined by the implementation for the
	 * specified session.
	 *
	 * @param session
	 * @param password
	 * @return true if user is authenticated
	 * @throws Exception if any errors occur or if user cannot be authenticated
	 */
	protected boolean authUser(Session session, byte[] password) throws Exception {
		_userinfo = session.getUserInfo();
		return true;
	}

	/**
	 * Handles the user auth banner message.
	 *
	 * In some jurisdictions, sending a warning message before authentication
	 * may be relevant for getting legal protection.  Many UNIX machines, for
	 * example, normally display text from /etc/issue, use TCP wrappers, or
	 * similar software to display a banner before issuing a login prompt.
	 *
	 * The SSH server may send an SSH_MSG_USERAUTH_BANNER message at any time
	 * after this authentication protocol starts and before authentication is
	 * successful.  This message contains text to be displayed to the client
	 * user before authentication is attempted.
	 * 
	 * By default, the client SHOULD display the 'message' on the screen.
	 * However, since the 'message' is likely to be sent for every login
	 * attempt, and since some client software will need to open a separate
	 * window for this warning, the client software may allow the user to
	 * explicitly disable the display of banners from the server.  The 'message'
	 * may consist of multiple lines, with line breaks indicated by CRLF pairs.
	 */
	protected void userAuthBanner() {
		// int		packet-length
		// byte		padding-length
		// byte		SSH_MSG_USERAUTH_BANNER(53)
		// string	message in ISO-10646 UTF-8 encoding [RFC3629]
		// string	language tag [RFC3066]
		_buffer.getInt();
		_buffer.getShort();
		if( _userinfo != null ) {
			// TODO Add configuration flag to disable displaying banner message
			_userinfo.showMessage(Util.byte2str(_buffer.getString()));
			//_buffer.getString();	// language
		}
	}

	/**
	 * Handles the user auth failure message.
	 *
	 * The 'authentications that can continue' is a comma-separated name-list of
	 * authentication 'method name' values that may productively continue the
	 * authentication dialog.
	 *
	 * It is RECOMMENDED that servers only include those 'method name' values in
	 * the name-list that are actually useful.  However, it is not illegal to
	 * include 'method name' values that cannot be used to authenticate the
	 * user.
	 *
	 * Already successfully completed authentications SHOULD NOT be included in
	 * the name-list, unless they should be performed again for some reason.
	 *
	 * The value of 'partial success' MUST be TRUE if the authentication request
	 * to which this is a response was successful.  It MUST be FALSE if the
	 * request was not successfully processed.
	 *
	 * @throws PartialAuthException if partial success flag not zero
	 */
	protected void userAuthFailure() throws PartialAuthException {
		// int		packet-length
		// byte		padding-length
		// byte		SSH_MSG_USERAUTH_FAILURE(51)
		// string	name list (of auth methods that can continue)
		// byte		partial success flag
		_buffer.getInt();
		_buffer.getShort();
		String nameList = Util.byte2str(_buffer.getString());
		if( this instanceof UserAuthNone || _buffer.getByte() != 0 ) {	// Partial success flag
			throw new PartialAuthException(nameList);
		}
	}

	/**
	 * Starts the SSH user authentication service and attempts to authorize the
	 * user with the preferred list of authentication methods.  The client
	 * preferences for user authentication methods can be set in the global or
	 * session configuration as a priority sorted list of method names with the
	 * property <code>SessionConfig.PREFERRED_AUTHS</code>.  If the user is
	 * successfully authenticated by the server then the method returns true.
	 * If authentication fails or is canceled by the user, then an exception is
	 * thrown.
	 *
	 * @param session to perform user authentication
	 * @param password
	 * @return true if the user is successfully authenticated for the session
	 * @throws Exception if any errors occur or if the user is not authenticated
	 */
	public static boolean authenticateUser(Session session, byte[] password) throws Exception {
		// Retrieve list of preferred client user auth methods
		LinkedList<String> clientMethods = new LinkedList<String>(session.getConfig().getList(SessionConfig.PREFFERED_AUTHS));
		if( clientMethods.isEmpty() ) {
			throw new JSchException("UserAuth failure, no client preferred authentication methods in config");
		}
		clientMethods.addFirst(UserAuth.NONE);	// Add 'none' first to retrieve available server methods

		// Request User Auth service to being auth process
		sendUserAuthInit(session);

		boolean authCanceled = false;
		Set<String> serverMethods = new HashSet<String>(Arrays.asList(UserAuth.NONE));
		UserAuth userAuth;

		// Attempt to perform user auth using each of the client preferred methods
		for( String userAuthMethod : clientMethods ) {
			// 'none' can always be sent, otherwise check if auth method is supported by server
			// TODO Add config override to allow sending auth methods even if not listed as supported
			if( !UserAuth.NONE.equals(userAuthMethod) && !serverMethods.contains(userAuthMethod) ) {
				continue;	// Server does not support user auth method, skip
			}
			JSch.getLogger().log(Level.INFO, "Authentication methods that can continue: " + (serverMethods != null ? serverMethods : NONE));
			JSch.getLogger().log(Level.INFO, "Current authentication method: " + userAuthMethod);

			try {	// Attempt to create UserAuth method instance
				userAuth = session.getConfig().getClassImpl(Algorithms.USERAUTH + userAuthMethod);
			} catch(Exception e) {
				JSch.getLogger().log(Level.WARN, "Failed to load UserAuth method '" + userAuthMethod + "': "+e, e);
				continue;	// Attempt next user auth method since this one failed/not supported...
			}

			authCanceled = false;
			try {
				// Attempt to authenticate user with method
				if( userAuth.authUser(session, password) ) {
					JSch.getLogger().log(Level.INFO, "Authentication succeeded, method: " + userAuthMethod);
					return true;	// Return true since user has been authed!
				}
			} catch(AuthCancelException ee) {
				authCanceled = true;
			} catch(PartialAuthException pe) {
				authCanceled = false;
				serverMethods = pe.getUserAuthMethods();	// Update server list of user auth methods
			}
		}

		// If not authenticated, throw appropriate exception
		if( authCanceled ) {
			throw new AuthCancelException("User authentication canceled by user");
		}
		throw new JSchException("User authentication failed");
	}

	/**
	 * Sends an SSH request to start the user authentication service.  If the
	 * request fails or is rejected by server, an exception is thrown.
	 *
	 * @param session to request user auth service
	 * @throws Exception if request fails or services is rejected by server
	 */
	static void sendUserAuthInit(Session session) throws Exception {
		// send user auth request
		// byte      SSH_MSG_SERVICE_REQUEST(5)
		// string    service name "ssh-userauth"
		Buffer buffer = new Buffer(100);
		Packet packet = new Packet(buffer);
		packet.reset();
		buffer.putByte(SSH_MSG_SERVICE_REQUEST);
		buffer.putString(SSH_USERAUTH);
		session.write(packet);
		JSch.getLogger().log(Level.INFO, "SSH_MSG_SERVICE_REQUEST for UserAuth sent");

		// receive user auth response
		// byte      SSH_MSG_SERVICE_ACCEPT(6)
		// string    service name
		if( session.read(buffer).getCommand() != SSH_MSG_SERVICE_ACCEPT ) {
			throw new JSchException("UserAuth service failed, expected SSH_MSG_SERVICE_ACCEPT(6): "+buffer.getCommand());
		}
		JSch.getLogger().log(Level.INFO, "SSH_MSG_SERVICE_ACCEPT for UserAuth received");
	}

	/**
	 * Creates the prompt for asking username/password.
	 *
	 * @param session
	 * @return password prompt
	 */
	static String createPasswordPrompt(Session session) {
		StringBuilder sbuffer = new StringBuilder(50);
		sbuffer.append(session.getUserName()).append('@').append(session.getHost());
		if( session.getPort() != SSHConstants.DEFAULT_SSH_PORT ) {
			sbuffer.append(':').append(session.getPort());
		}
		return sbuffer.toString();
	}

}
