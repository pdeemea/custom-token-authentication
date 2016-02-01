package pivotal.io.demo.customtoken.security;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;


public class PreAuthenticatedFilter extends GenericFilterBean {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		Authentication auth = SecurityContextHolder.getContext().getAuthentication(); 
		
		if (auth == null || auth instanceof AnonymousAuthenticationToken) {
			SecurityContextHolder.getContext().setAuthentication(
					createAuthentication((HttpServletRequest) request));
		}

		chain.doFilter(request, response);
	}

	protected Authentication createAuthentication(HttpServletRequest request) {
		AuthenticatedUser auth = new AuthenticatedUser(new UsernamePasswordAuthenticationToken("bob","password", 
				authorities(SecurityRoles.USER, SecurityRoles.ADMIN)),
				"organization");
		return auth;
	}
	protected Collection<GrantedAuthority> authorities(String ... roles) {
		return Arrays.asList(roles).stream().map(r -> new SimpleGrantedAuthority(r)).collect(Collectors.toList());
	}
}
