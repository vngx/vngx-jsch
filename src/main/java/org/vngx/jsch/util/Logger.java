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

package org.vngx.jsch.util;

import java.util.Arrays;

/**
 * <p>Interface for defining a simple logger for the SSH library to reduce any
 * external dependencies which would be required for logging libraries such as
 * log4j, slf4j, et al.  Implementations of <code>Logger</code> can be used to
 * wrap an external logging framework to allow for logging integration.</p>
 *
 * <p>Two default implementations are provided in the interface:
 * <ul>
 *	<li><code>SIMPLE_LOGGER</code> - Logs all output to System.err</li>
 *	<li><code>NULL_LOGGER</code> - Empty logger to ignore output</li>
 * </ul>
 * </p>
 *
 * <p>The <code>Logger</code> instance is set by calling
 * {@link org.vngx.jsch.JSch#setLogger(org.vngx.jsch.util.Logger)}</p>
 *
 * @see org.vngx.jsch.JSch
 * 
 * @author Michael Laudati
 */
public interface Logger {

	/** Enum constants for logging levels. */
	enum Level {
		/** Debug level for logging. */
		DEBUG,
		/** Info level for logging. */
		INFO,
		/** Warn level for logging. */
		WARN,
		/** Error level for logging. */
		ERROR,
		/** Fatal level for logging. */
		FATAL
	}

	/**
	 * Returns true if the specified logging <code>Level</code> is enabled.
	 *
	 * @param level to check
	 * @return true if logging level is enabled
	 */
	boolean isEnabled(Level level);

	/**
	 * Logs the specified message at the specified logging level.
	 *
	 * @param level to log
	 * @param message to log
	 */
	void log(Level level, String message);

	/**
	 * Logs the specified message and arguments at the specified level.
	 *
	 * @param level
	 * @param message
	 * @param args
	 */
	void log(Level level, String message, Object... args);

	/**
	 * Logs the specified message and exception at the specified level.
	 * 
	 * @param level
	 * @param message
	 * @param exception
	 */
	void log(Level level, String message, Throwable exception);

	/**
	 * Simple implementation of <code>Logger</code> interface which logs all
	 * output to the <code>System.err</code> stream.
	 */
	Logger SIMPLE_LOGGER = new Logger() {

		@Override public boolean isEnabled(Level level) { return true; }

		@Override public void log(Level level, String message) { System.err.println(message); }

		@Override public void log(Level level, String message, Object... args) {
			System.err.print(message);
			if( args != null ) {
				System.err.print(": ");
				System.err.println(Arrays.asList(args));
			}
		}

		@Override public void log(Level level, String message, Throwable exception) {
			System.err.println(message+": "+exception);
			if( exception != null ) {
				exception.printStackTrace(System.err);
			}
		}
	};

	/**
	 * Null implementation of <code>Logger</code> which ignores all logging
	 * output.
	 */
	Logger NULL_LOGGER = new Logger() {

		@Override public boolean isEnabled(Level level) { return false; }

		@Override public void log(Level level, String message) { }

		@Override public void log(Level level, String message, Object... args) { }

		@Override public void log(Level level, String message, Throwable exception) { }
		
	};
	
}
