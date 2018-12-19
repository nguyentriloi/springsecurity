package com.loiclude.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface UserDetailsService{
	
	public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException;
}
