package pivotal.io.demo.customtoken.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import pivotal.io.demo.customtoken.security.AuthenticatedUser;
import pivotal.io.demo.customtoken.security.CurrentAuthenticatedUser;
import pivotal.io.demo.customtoken.services.SomeService;

@Controller
public class SomeServiceController {

	@Autowired private SomeService someService;
	
	@RequestMapping(value = "/doSomeRead") 
	public String doSomeRead(@CurrentAuthenticatedUser AuthenticatedUser user) {
		someService.doSomeRead(user);
		return "home";
	}
	
	@RequestMapping(value = "/doSomeWrites") 
	public String doSomeWrites() {
		someService.doSomeWrites();
		return "home";
	}
	
	
	@RequestMapping(value = "/doSomeThing") 
	public String doSomeRead() {
		System.out.println("Called doSomething");
		return "home";
	}
}
