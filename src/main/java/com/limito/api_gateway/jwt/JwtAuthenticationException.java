package com.limito.api_gateway.jwt;

public class JwtAuthenticationException extends RuntimeException {
	public JwtAuthenticationException(String message, Throwable cause) {
		super(message, cause);
	}
}
