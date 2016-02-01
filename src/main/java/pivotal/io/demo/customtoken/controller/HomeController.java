package pivotal.io.demo.customtoken.controller;

import java.security.Principal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import pivotal.io.demo.customtoken.security.AuthenticatedUser;
import pivotal.io.demo.customtoken.security.CurrentAuthenticatedUser;
import pivotal.io.demo.customtoken.services.SomeService;

@Controller
@PreAuthorize("hasRole('ROLE_USER')")
public class HomeController {

	@RequestMapping(value = "/home") 
	public String home(@CurrentAuthenticatedUser AuthenticatedUser principal) {
		return "home";
	}
	
	@RequestMapping(value = "/produceException") 
	public String produceException() {
		throw new RuntimeException("Some simulated exception");
	}
	
	@PreAuthorize("hasRole('ROLE_SPECIAL')")
	@RequestMapping(value = "/special") 
	public String special() {
		return "home";
	}
	
		
}
