package org.keycloak.protocol.saml.mappers;

/**
 * Indicates that an error had occurred when the mapper is attempting to process a request.
 */
public class MapperProcessingException extends RuntimeException {

	public MapperProcessingException() {
	}

	public MapperProcessingException(final String message) {
		super(message);
	}

	public MapperProcessingException(final String message, final Throwable cause) {
		super(message, cause);
	}

	public MapperProcessingException(final Throwable cause) {
		super(cause);
	}

	public MapperProcessingException(final String message, final Throwable cause, final boolean enableSuppression, final boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}
}
