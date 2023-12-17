package io.spring.authorizationserver.config;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	@Order(1)
	public SecurityFilterChain webSecurityfilterChainForOauth(HttpSecurity httpSecurity) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);

		httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
					.oidc(Customizer.withDefaults());

		httpSecurity.exceptionHandling(e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

		return httpSecurity.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain appSecurityfilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.authorizeHttpRequests(request -> request.anyRequest().authenticated())
			.formLogin(Customizer.withDefaults());		
		return httpSecurity.build();
	}
	
	@Bean
	public UserDetailsService userDetailsService() {
		var user = User.withUsername("gokul")
				.password("test")
				.authorities("read")
				.build();
		
		return new InMemoryUserDetailsManager(user);
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
	
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		var registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("gokul-client")
				.clientSecret("gokul-secret")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.redirectUri("http://127.0.0.1:4200/login/oauth2/code/gokul-client")
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.authorizationGrantTypes(grantType ->{
//					grantType.add(AuthorizationGrantType.DEVICE_CODE);
					grantType.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
					grantType.add(AuthorizationGrantType.AUTHORIZATION_CODE);
					grantType.add(AuthorizationGrantType.REFRESH_TOKEN);
				}).clientSettings(ClientSettings.builder().requireProofKey(true).build()).build();
		
		return new InMemoryRegisteredClientRepository(registeredClient);
	}
	
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}
	
	@Bean
	public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException{
		KeyPairGenerator keyPairGenerator= KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		
		var keys = keyPairGenerator.generateKeyPair();
		var publicKey = (RSAPublicKey) keys.getPublic();
		var privateKey = keys.getPrivate();
		var rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
		return new ImmutableJWKSet<>(new JWKSet(rsaKey));
	}
	
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

}
