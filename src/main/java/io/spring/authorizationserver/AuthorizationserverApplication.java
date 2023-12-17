package io.spring.authorizationserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@SpringBootApplication
public class AuthorizationserverApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationserverApplication.class, args);
	}
//	@Bean
//	InMemoryUserDetailsManager inMemoryUserDetailsManager() {
//		return new InMemoryUserDetailsManager(User.withDefaultPasswordEncoder()
//				.roles("admin").username("gokul").password("test").build());
//	}

}
