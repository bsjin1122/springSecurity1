package org.zerock.testsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public RoleHierarchy roleHierarchy() {

		RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();

		hierarchy.setHierarchy("ROLE_C > ROLE_B\n" +
			"ROLE_B > ROLE_A");

		return hierarchy;
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {

		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

		// http
		// 	.authorizeHttpRequests((auth) -> auth
		// 		.requestMatchers("/", "/login", "/loginProc", "/join", "/joinProc").permitAll()
		// 		.requestMatchers("/admin").hasRole("ADMIN")
		// 		.requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
		// 		.anyRequest().authenticated()
		// 	);
		http
			.authorizeHttpRequests((auth) -> auth
				.requestMatchers("/login").permitAll()
				.requestMatchers("/").hasAnyRole("A", "B", "C")
				.requestMatchers("/manager").hasAnyRole("B", "C")
				.requestMatchers("/admin").hasAnyRole("C")
				.anyRequest().authenticated()
			);



		http
			.formLogin((auth) -> auth.loginPage("/login")
				.loginProcessingUrl("/loginProc")
				.permitAll()
			);

		// http
		// 	.csrf((auth) -> auth.disable());

		http
			.sessionManagement((auth) -> auth
				.maximumSessions(1)
				.maxSessionsPreventsLogin(true));
		http
			.logout((auth) -> auth.logoutUrl("/logout")
				.logoutSuccessUrl("/"));

		return http.build();
	}

	/* DB를 사용하지 않고, 소수의 사용자만 등록해서 사용하고 싶은 경우.
	@Bean
	public UserDetailsService userDetailsService() {

		UserDetails user1 = User.builder()
			.username("user1")
			.password(bCryptPasswordEncoder().encode("1234"))
			.roles("ADMIN")
			.build();

		UserDetails user2 = User.builder()
			.username("user2")
			.password(bCryptPasswordEncoder().encode("1234"))
			.roles("USER")
			.build();

		return new InMemoryUserDetailsManager(user1, user2);
	}*/
}