package com.loiclude.utils;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class WebUtils {
	public static String toString(User user) {
		StringBuilder sb = new StringBuilder();
		sb.append("username : ").append(user.getUsername());
		
		Collection<GrantedAuthority> authorities = user.getAuthorities();
		if(authorities != null  && !authorities.isEmpty()) {
			sb.append(" (");
			boolean first = true;
			for (GrantedAuthority grantedAuthority : authorities) {
				if(first) {
					sb.append(grantedAuthority.getAuthority());
					first = false;
					
				}else {
					sb.append(", ").append(grantedAuthority.getAuthority());
				}
			}
			sb.append("");
		}
		return sb.toString();
	}
}
