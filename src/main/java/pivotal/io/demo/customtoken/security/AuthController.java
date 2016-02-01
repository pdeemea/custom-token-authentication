package pivotal.io.demo.customtoken.security;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {

	@Value("${login.url:/login}")
	private String loginUrl;

	@Value("${home.url:/home}")
	private String homeUrl;

	@Autowired
	private AuthenticationManager authProvider;

	
	@RequestMapping(value = "/auth", method = { RequestMethod.POST, RequestMethod.GET })
	public String auth(@RequestParam(required=false) String token, Principal principal, HttpServletRequest request,
			HttpServletResponse response) {
		if (principal != null) {
			return "redirect:" + homeUrl;
		}

		if (StringUtils.isEmpty(token)) {
			throw new AuthenticationCredentialsNotFoundException("token not found");
		}
		
			// validate+authenticate token
		Authentication auth = authenticate(token);
		SecurityContextHolder.getContext().setAuthentication(auth);
		
		return "redirect:" + homeUrl;

	}

	// This method encapsulates how our application authenticates or validates a token. In our case, it is 
	// very simple, if the token follows the pattern <string1>:<string2>, string1 becomes the username and
	// string2 is the credential. Additionally, we are enforcing that the user must exist in the local authenticator
	// injected by Spring. 
	private Authentication authenticate(String token) {
		String[] t = token.split(":");
		if (t.length > 1) {
			UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(t[0], t[1]);
			return new AuthenticatedUser(authProvider.authenticate(auth), "someOrganization");
		} else {
			// we could throw other type of exceptions and we can handle them right on this same @Controller class
			throw new InternalAuthenticationServiceException("invalid token");
		}
	}
	

	
	@ExceptionHandler({InternalAuthenticationServiceException.class})
	public void handleFailedLogin(HttpServletResponse response) throws IOException {
		System.err.println("InternalAuthenticationServiceException " );
		response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value());	
	}
	
	@ExceptionHandler({AuthenticationCredentialsNotFoundException.class})
	public String credentialsNotFound() {
		System.err.println("Credentials not found Exception");
		return "redirect:" + loginUrl;	
	}
	
}
