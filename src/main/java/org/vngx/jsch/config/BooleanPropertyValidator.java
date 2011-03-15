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
 * Implementation of {@code PropertyValidator} which validates a property value
 * by checking if it's a {@code boolean}.
 *
 * @author Michael Laudati
 */
public class BooleanPropertyValidator extends PropertyValidator {

    /** Boolean property validator with default value of true. */
    public final static BooleanPropertyValidator DEFAULT_TRUE_VALIDATOR = new BooleanPropertyValidator(true);
    /** Boolean property validator with default value of false. */
    public final static BooleanPropertyValidator DEFAULT_FALSE_VALIDATOR = new BooleanPropertyValidator(false);
    
    
    /**
     * Creates a new instance of {@code BooleanPropertyValidator} with the
     * default boolean value.
     * 
     * @param defaultValue of boolean property
     */
    protected BooleanPropertyValidator(boolean defaultValue) {
        super(String.valueOf(defaultValue));
    }

	/**
	 * Returns {@code true} if the specified property {@code value} can be
	 * parsed by {@link Boolean#valueOf(java.lang.String).
	 *
	 * @param value to validate
	 * @return {@code true} if property value is a boolean
	 */
    @Override
    protected boolean isPropertyValid(String value) {
        try {
            Boolean.valueOf(value);
            return true;
        } catch(Exception e) {
            return false;
        }
    }
    
}
