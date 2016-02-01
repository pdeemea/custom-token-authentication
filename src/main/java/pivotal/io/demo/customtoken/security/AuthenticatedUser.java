package pivotal.io.demo.customtoken.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

public class AuthenticatedUser extends UsernamePasswordAuthenticationToken {

	/**
	 * 
	 */
	private static final long serialVersionUID = -2821932805440227825L;

	final private String organization;
	
	public AuthenticatedUser(Authentication token, String organization) {
		super(token.getPrincipal(), token.getCredentials(), token.getAuthorities());
		this.organization = organization;
	}

	public String getOrganization() {
		return organization;
	}
	public String getUsername() {
		return ((UserDetails)getPrincipal()).getUsername();
	}
	
}
