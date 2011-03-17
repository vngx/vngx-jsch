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

package org.vngx.jsch;

/**
 * <p>An interface defining an API for a user interface to retrieve user input
 * and display messages.  Implementations should take care to provide the best
 * security practices when dealing with passwords and passphrases.  Prompts
 * should mask any sensitive input data and ensure the values are stored safely.
 * </p>
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public interface UserInfo {

	/**
	 * <p>Returns the passphrase provided by the user after a successful call to
	 * {@link #promptPassphrase(java.lang.String)}.  Implementations should
	 * take care to mask the passphrase characters to prevent an eavesdropper
	 * from viewing sensitive credentials.  A {@code null} return value
	 * indicates the user declined to enter a passphrase.</p>
	 *
	 * @return passphrase entered by user or null if none provided
	 */
	String getPassphrase();	// TODO Consider returning byte[]

	/**
	 * <p>Returns the password provided by the user after a successful call to
	 * {@link #promptPassword(java.lang.String)}.  Implementations should
	 * take care to mask the password characters to prevent an eavesdropper
	 * from viewing sensitive credentials.  A {@code null} return value
	 * indicates the user declined to enter a password.</p>
	 *
	 * @return password entered by user or null if none provided
	 */
	String getPassword(); // TODO Consider returning byte[]

	/**
	 * <p>Prompts the user with the specified {@code message} to enter a
	 * password.  The password should be stored in such a way that it can be
	 * retrieved with {@link #getPassword()}.  Implementations should honor
	 * best security practices by masking the password input.  The method should
	 * return {@code true} if the user successfully provided a password; if the
	 * user cancels/declines the password prompt, then {@code false} should be
	 * returned.</p>
	 *
	 * @param message to display when prompting user for password
	 * @return {@code true} if user entered password, {@code false} if user
	 *			canceled/declined password prompt
	 */
	boolean promptPassword(String message);

	/**
	 * <p>Prompts the user with the specified {@code message} to enter a
	 * passphrase.  The passphrase should be stored in such a way that it can be
	 * retrieved with {@link #getPassphrase()}.  Implementations should honor
	 * best security practices by masking the passphrase input. The method should
	 * return {@code true} if the user successfully provided a passphrase; if
	 * the user cancels/declines the passphrase prompt, then {@code false}
	 * should be returned.</p>
	 *
	 * @param message to display when prompting user for passphrase
	 * @return {@code true} if user entered passphrase, {@code false} if user
	 *			canceled/declined passphrase prompt
	 */
	boolean promptPassphrase(String message);

	/**
	 * <p>Prompts the user with the specified {@code message} and allows for a
	 * yes ({@code true}) or no ({@code false}) response.</p>
	 *
	 * @param message to display
	 * @return {@code true} if user selected yes
	 */
	boolean promptYesNo(String message);

	/**
	 * <p>Displays the specified {@code message} to the user.</p>
	 *
	 * @param message to display
	 */
	void showMessage(String message);

}
