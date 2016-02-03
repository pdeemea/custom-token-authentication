# custom-token-authentication
Proof of Concept to demonstrate how to implement custom token authentication within a Spring/Spring Boot

Goals:

1. Demonstrate how to add custom token authentication. The recommended way is to create a SecurityFilter and add it to the security filter like others filters like `BasicAuthenticationFilter`. But instead we handle the authentication in a `@Controller` class.
2. Demonstrate how to add a pre-authentication filter that allows a developer to run their applications locally without having to login every time they start their apps. This filter, on the other hand, it is added as a SecurityFilter and it works pretty as the `AnonymousAuthenticationFilter` does. 
I think another way to achieve this goal but i have not tried it yet is to rely on BasicAuthentication and configure the roles for the default user in the `application.yml` and rely on the browser to remain your user´s credentials. we would only have to activate the basic Authentication rather than adding our custom filter `PreAuthenticationFilter`. It is worth trying this one.

To demonstrate goal 1 you just need to run the app as it is.
To demonstrate goal 2 though you need to activate the profile `preAuth`. The user, credential and roles are read from the `application.yml`.

Issues pending to be resolved:
- Management endpoint roles is not enforced. In other words, as long as the user is fully authenticated, I am allowed to access any endpoint. The role does not appear to be enforced.
