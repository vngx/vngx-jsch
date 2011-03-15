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
 * Simple property value validator which provides two methods; one to check if a
 * given property value is valid, and another to return a default value for a
 * property.  Subclasses can override the {@link #isPropertyValid(java.lang.String)}
 * method to provide custom validation logic.
 *
 * @author Michael Laudati
 */
public class PropertyValidator {

    /** Default property value. */
    protected final String _defaultValue;


    /**
     * Creates a new instance of {@code DefaultPropertyValidator} with
     * the specified default value.
     *
     * @param defaultValue of property
     */
    public PropertyValidator(final String defaultValue) {
        _defaultValue = defaultValue;
    }

	/**
	 * Returns true if the specified {@code property} value is valid as defined
	 * by the implementation.  By default, the method returns true if the value
	 * is not null.
	 *
	 * @param property value to validate
	 * @return true if property is not null
	 */
    protected boolean isPropertyValid(String property) {
        return property != null;
    }

	/**
	 * Returns the default value for this property validator.
	 *
	 * @return default value
	 */
	protected String getDefaultValue() {
        return _defaultValue;
    }

}
