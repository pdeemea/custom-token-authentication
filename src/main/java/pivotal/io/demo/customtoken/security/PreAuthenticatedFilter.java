package pivotal.io.demo.customtoken.security;

import java.io.IOException;
import java.util.Collection;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.OncePerRequestFilter;


public class PreAuthenticatedFilter extends OncePerRequestFilter {

	private PreAuthenticationConfiguration config;
	
	public PreAuthenticatedFilter(PreAuthenticationConfiguration config) {
		this.config = config;
	}
	
	protected Authentication createAuthentication(HttpServletRequest request) {
		Collection<GrantedAuthority>  authorities = authorities(config.getRoles());
		AuthenticatedUser auth = new AuthenticatedUser(new UsernamePasswordAuthenticationToken(new User(config.getUsername(), config.getCredential(), authorities), 
				config.getCredential(), authorities), config.getOrganization());
		return auth;
	}
	protected Collection<GrantedAuthority> authorities(Collection<String> roles) {
		return roles.stream().map(r -> new SimpleGrantedAuthority("ROLE_" + r)).collect(Collectors.toList());
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication(); 
		
		if (auth == null || auth instanceof AnonymousAuthenticationToken) {
			SecurityContextHolder.getContext().setAuthentication(
					createAuthentication((HttpServletRequest) request));
		}

		filterChain.doFilter(request, response);
		
	}
}
