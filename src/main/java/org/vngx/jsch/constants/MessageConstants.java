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
 * Constants for user messages.
 *
 * @author Michael Laudati
 */
public interface MessageConstants {

	/**
	 * Message prompt displayed to user if the host key has changed compared
	 * to what's stored in locally known hosts.
	 *
	 * Args:
	 *	1) Host key algorithm
	 *	2) Host key fingerprint
	 *	3) Known hosts file
	 */
	String INVALID_SERVER_HOST =
			"WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n" +
			"IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n" +
			"Someone could be eavesdropping on you right now (man-in-the-middle attack)!\n" +
			"It is also possible that the %1$s host key has just been changed.\n" +
			"The fingerprint for the %1$s key sent by the remote host is\n" + "%2$s.\n" +
			"Please contact your system administrator.\n" +
			"Add correct host key in %3$s to get rid of this message.";

	/** Prompt user if they want to replace old key with new key. */
	String PROMPT_REPLACE_KEY = INVALID_SERVER_HOST +
			"\nDo you want to delete the old key and insert the new key?";

	/**
	 * Message prompt displayed to user if an unknown host key is sent by
	 * server and StrictHostKeyChecking is set to 'ask'.
	 *
	 * Args:
	 *	1) Host
	 *	2) Host key algorithm
	 *	3) Host key fingerprint
	 */
	String PROMPT_UNKNOWN_KEY =
			"The authenticity of host '%1$s' can't be established.\n" +
			"%2$s key fingerprint is %3$s.\n" +
			"Are you sure you want to continue connecting?";

	/**
	 * Message prompt displayed to ask user for password for a given host.
	 *
	 * Args:
	 *	1) Host:port
	 */
	String PROMPT_PASSWORD = "Password for %1$s";

	/**
	 * Message prompt displayed to ask user for passphrase for a given key.
	 *
	 * Args:
	 *	1) Public key name
	 */
	String PROMPT_PASSPHRASE = "Passphrase for %1$s";

	/** Message prompt indicating password must be changed. */
	String PASSWORD_MUST_CHANGE = "Password must be changed.";

	/**
	 * Message prompt to ask user if they approve creating a known hosts
	 * repository file.
	 *
	 * Args:
	 *	1) known hosts file name
	 */
	String PROMPT_CREATE_KNOWN_HOSTS =
			"%1$s does not exist.\n" +
			"Are you sure you want to create it?";

	/**
	 * Message prompt to ask user if they approve creating known hosts
	 * directory.
	 *
	 * Args:
	 *	1) Directory file name
	 */
	String PROMPT_CREATE_HOSTS_DIR =
			"The parent directory %1$s does not exist.\n" +
			"Are you sure you want to create it?";

	String MSG_KNOWN_HOSTS_NOT_CREATED =
			"%1$s has not been created.";
	
	String MSG_KNOWN_HOSTS_CREATED =
			"%1$s has been succesfully created.\n"
			+ "Please check its access permission.";

}
