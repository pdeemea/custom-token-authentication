package pivotal.io.demo.customtoken.services;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import pivotal.io.demo.customtoken.security.AuthenticatedUser;
import pivotal.io.demo.customtoken.security.CurrentAuthenticatedUser;

@PreAuthorize("hasRole('ROLE_USER')")
@Service
public class SomeService {

	public void doSomeRead(AuthenticatedUser principal) {
		// we can do further checks using principal
		System.out.println("Further checks on " + principal.getUsername());
	}
	@PreAuthorize("hasRole('ROLE_SOME_WRITE')")
	public void doSomeWrites() {
		
	}
}
