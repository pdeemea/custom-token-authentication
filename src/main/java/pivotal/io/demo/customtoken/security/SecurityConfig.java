package pivotal.io.demo.customtoken.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.web.DefaultErrorAttributes;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import pivotal.io.demo.customtoken.controller.GlobalErrorController;


@Configuration
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class SecurityConfig {

	@Autowired
	private ServerProperties properties;
	
	@Autowired
 	private Environment env;
 	
	
	 @Bean
	 @Profile("token-login")
	 public WebSecurityConfigurerAdapter config() {
		 return new CustomTokenConfig(env);
	 }
	 
	 @Bean
	 @Profile("self-login")
	 public WebSecurityConfigurerAdapter selfLogin() {
		 return new SelfLoginConfig(new PreAuthenticatedFilter());
	 }
	 
	 @Bean
	 public GlobalErrorController globalErrorController() {
		 return new GlobalErrorController(new DefaultErrorAttributes(), properties.getError());
	 }
//	 @Bean
//	 public GlobalRestErrorController globalRestErrorController() {
//		 return new GlobalRestErrorController();
//	 }
	 

	 @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
	 static class SelfLoginConfig extends WebSecurityConfigurerAdapter {
		 
		 	PreAuthenticatedFilter filter;
		 	
		 	SelfLoginConfig(PreAuthenticatedFilter filter) {
		 		this.filter = filter;
		 	}
		 	
			@Override
			protected void configure(HttpSecurity http) throws Exception {
				http.addFilterAfter(filter, LogoutFilter.class);
			}
	 }
	 
	
	 @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
	  static class CustomTokenConfig extends WebSecurityConfigurerAdapter {
		 
		 	private Environment env;
		 	
		 	CustomTokenConfig(Environment env) {
		 		super();
		 		this.env = env;
		 	}
		 	
		    @Override
			public void configure(WebSecurity web) throws Exception {
				web.ignoring().antMatchers( "/index.html", "/");
			}
		    
			@Override
			protected void configure(HttpSecurity http) throws Exception {
			
				configureLogout(http);
				disableFeatures(http);
				redirectUnauthenticatedUsers(http);
				
				http.authorizeRequests().antMatchers("/auth", "/logout").permitAll()
				    					.anyRequest().authenticated();
					
			}
			
			private void redirectUnauthenticatedUsers(HttpSecurity http) throws Exception {
				http.exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(env.getProperty("login.url")));
			}

			private void disableFeatures(HttpSecurity http) throws Exception {
				http.rememberMe().disable();
				// we cannot disable csrf because we are not doing a RESTful-api application but rather a UI-based 
				// if this were a Restful app, we could disable csrf and GET logout would not have given us any problems 
				
			}
			
			private void configureLogout(HttpSecurity http) throws Exception {
				LogoutConfigurer<HttpSecurity> logout = http.logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
				
				if (env.acceptsProfiles("clustered")) {
					logout.addLogoutHandler(new RemoveRemoteSession());	
				}
				logout.logoutSuccessUrl("/");

			}
			
			@Autowired
			public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
				
			    auth.inMemoryAuthentication()
			      .withUser("bob").password("pwd").roles(SecurityRoles.USER, SecurityRoles.OTHER)
			    .and()
			      .withUser("bill").password("pwd").roles(SecurityRoles.USER, SecurityRoles.OTHER)
			    .and()
			      .withUser("admin").password("pwd").roles(SecurityRoles.USER, SecurityRoles.ADMIN);
			  }
		}
}
