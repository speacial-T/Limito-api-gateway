package com.limito.api_gateway.filter;

import org.apache.http.HttpHeaders;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import com.limito.api_gateway.jwt.AuthUserInfo;
import com.limito.api_gateway.jwt.JwtAuthenticationException;
import com.limito.api_gateway.jwt.JwtTokenProvider;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {
	private final JwtTokenProvider jwtTokenProvider;

	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

		String path = exchange.getRequest().getURI().getPath();

		// 기본 API는 바로 통과
		if (isPublicPath(path)) {
			return chain.filter(exchange);
		}

		// Authorization 헤더에서 Bearer 토큰 추출
		String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "MISSING AUTHORIZATION HEADER");
		}

		String token = authHeader.substring(7);

		AuthUserInfo userInfo;
		try {
			userInfo = jwtTokenProvider.parseAccessToken(token);
		} catch (JwtAuthenticationException e) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, e.getMessage());
		}

		// 도메인 서비스로 보내는 요청에 X-User-* 헤더 세팅
		var mutatedRequest = exchange.getRequest()
			.mutate()
			.header("X-User-Id", String.valueOf(userInfo.getUserId()))
			.header("X-User-Email", userInfo.getEmail())
			.header("X-User-Role", userInfo.getRole())
			.build();

		var mutatedExchange = exchange.mutate()
			.request(mutatedRequest)
			.build();

		return chain.filter(mutatedExchange);
		// 다른 필터보다 앞에서 올림
	}

	// 기본 API
	private boolean isPublicPath(String path) {
		return path.startsWith("/api/v1/users/signup")  // 일반 회원가입
			|| path.startsWith("/api/v1/users/admin/signup") // 관리자 회원가입
			|| path.startsWith("/api/v1/users/login")  // 로그인
			|| path.startsWith("/actuator/health");
	}

	@Override
	public int getOrder() {
		return -10;
	}
}
