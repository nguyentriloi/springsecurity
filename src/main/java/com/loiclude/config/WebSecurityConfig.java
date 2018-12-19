package com.loiclude.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import com.loiclude.service.impl.UserDetailsServiceImpl;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private UserDetailsServiceImpl serviceImpl;
	
	@Autowired
	private DataSource dataSource;
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
		return bCryptPasswordEncoder;
	}
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception{
		//set dat dich vu de tim kiem User trong Database
		//va set dat passwordEncoder
		auth.userDetailsService(userDetailsServiceBean()).passwordEncoder(passwordEncoder());
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		http.csrf().disable();
		
		//cac trang khong yeu cau login
		http.authorizeRequests().antMatchers("/","login","/logout").permitAll();
		
		// trang /userInfo yeu cau phai login voi vai tro ROLE_USER hoac ROLE_ADMIN
		//Neu chua login, no se redirect toi trang /login
		http.authorizeRequests().antMatchers("/userInfo").access("hasAnyRole('ROLE_USER','ROLE_ADMIN')");
		
		//Trang chi danh cho ADMIN 
		http.authorizeRequests().antMatchers("/admin").access("hasRole('ROLE_ADMIN')");
		
		//khi nguoi dung da login, voi vai tro XX
		//Nhung khi truy cap vao trang yeu cau vai tro YY
		//Ngoai le AccessDeniedException se nem ra
		http.authorizeRequests().and().exceptionHandling().accessDeniedPage("/403");
		
		//cau hinh cho login form 
		http.authorizeRequests().and().formLogin()//
			//submit url cua trang login
			.loginProcessingUrl("/j_spring_security_check") //submit url
			.loginPage("/login")//
			.defaultSuccessUrl("/userAccountInfo")//
			.failureUrl("/login?error=true")//
			.usernameParameter("username")//
			.passwordParameter("password")
			//cau hinh cho logout page
			.and().logout().logoutUrl("/logout").logoutSuccessUrl("/logoutSuccessful");
			
		//cau hinh remember me
		http.authorizeRequests().and()//
			.rememberMe().tokenRepository(this.persistentTokenRepository())//
			.tokenValiditySeconds(1*24*60*60); //24h
	}
	
	@Bean
	public PersistentTokenRepository persistentTokenRepository() {
		JdbcTokenRepositoryImpl db = new JdbcTokenRepositoryImpl();
		db.setDataSource(dataSource);
		return db;
	}
}
