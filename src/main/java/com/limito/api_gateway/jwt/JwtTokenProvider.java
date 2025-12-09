package com.limito.api_gateway.jwt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import com.limito.common.exception.AppException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

@Component
public class JwtTokenProvider {

	@Value("${security.jwt.secret-key}")
	private String secretKey;

	public AuthUserInfo parseAccessToken(String token) {
		try {
			Claims claims = Jwts.parser()
				.setSigningKey(secretKey)
				.build()
				.parseClaimsJws(token)
				.getBody();

			Long userId = Long.valueOf(claims.getSubject());
			String role = claims.get("X-User-Role", String.class);

			return new AuthUserInfo(userId, role);
		} catch (ExpiredJwtException e) {
			throw AppException.of(HttpStatus.UNAUTHORIZED, "ACCESS_TOKEN_EXPIRED");
		} catch (JwtException | IllegalArgumentException e) {
			throw AppException.of(HttpStatus.UNAUTHORIZED, "INVALID_ACCESS_TOKEN");
		}
	}
}
