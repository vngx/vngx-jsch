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

package org.vngx.jsch.config;

/**
 * Implementation of {@code PropertyValidator} for validating numeric properties
 * values.
 * 
 * @author Michael Laudati
 */
public class NumberPropertyValidator extends PropertyValidator {

	/**
	 * Creates a new instance of {@code NumberPropertyValidator} with the
	 * specified default value.
	 *
	 * @param defaultValue
	 */
	protected NumberPropertyValidator(int defaultValue) {
		super(String.valueOf(defaultValue));
	}

	/**
	 * Returns a {@code NumberPropertyValidator} which checks if the property is
	 * a valid {@code int} and has the specified default value.
	 *
	 * @param defaultValue of integer property
	 * @return validator
	 */
	public static NumberPropertyValidator createValidator(int defaultValue) {
		return new NumberPropertyValidator(defaultValue);
	}

	/**
	 * Returns a {@code NumberPropertyValidator} which checks if the property is
	 * a valid {@code int}, is greater than or equal to the {@code min} value
	 * and less than or equal to the {@code max} value.
	 *
	 * @param min value of property
	 * @param max value of property
	 * @param defaultValue of integer property
	 * @return validator
	 */
	public static NumberPropertyValidator createValidator(final int min, final int max, int defaultValue) {
		return new NumberPropertyValidator(defaultValue) {
			@Override protected boolean isPropertyValid(String property) {
				try {
					int value = Integer.parseInt(property);
					return value >= min && value <= max;
				} catch(Exception e) {
					return false;
				}
			}
		};
	}

	/**
	 * Returns a {@code NumberPropertyValidator} which checks if the property is
	 * a valid {@code int} and is greater than or equal to the {@code min}
	 * value.
	 *
	 * @param min value of property
	 * @param defaultValue of integer property
	 * @return validator
	 */
	public static NumberPropertyValidator createMinValidator(final int min, int defaultValue) {
		return new NumberPropertyValidator(defaultValue) {
			@Override protected boolean isPropertyValid(String property) {
				try {
					int value = Integer.parseInt(property);
					return value >= min;
				} catch(Exception e) {
					return false;
				}
			}
		};
	}

	/**
	 * Returns a {@code NumberPropertyValidator} which checks if the property is
	 * a valid {@code int} and less than or equal to the {@code max} value.
	 *
	 * @param max value of property
	 * @param defaultValue of integer property
	 * @return validator
	 */
	public static NumberPropertyValidator createMaxValidator(final int max, int defaultValue) {
		return new NumberPropertyValidator(defaultValue) {
			@Override protected boolean isPropertyValid(String property) {
				try {
					int value = Integer.parseInt(property);
					return value <= max;
				} catch(Exception e) {
					return false;
				}
			}
		};
	}

	@Override
	protected boolean isPropertyValid(String property) {
		return isInteger(property);
	}

	/**
	 * Returns true if the specified property is not null and is an integer.
	 *
	 * @param property value to check if integer
	 * @return true if value is integer
	 */
	protected static boolean isInteger(String property) {
		try {
			Integer.parseInt(property);
			return true;
		} catch(Exception e) {
			return false;
		}
	}

}
