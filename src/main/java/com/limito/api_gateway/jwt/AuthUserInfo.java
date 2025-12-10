package com.limito.api_gateway.jwt;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class AuthUserInfo {
	private Long userId;
	private String email;
	private String role;
}
