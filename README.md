# custom-token-authentication
Proof of Concept to demonstrate how to implement custom token authentication within a Spring/Spring Boot application.

Goals:

1. Demonstrate how to add custom token authentication. The recommended way is to add an authentication endpoint, i.e. a `@Controller`, and the authentication thru that controller. This is contrary to standard off-the-shelf authentication methods like `BasicAuthenticationFilter` which are implemented as Filters and are added to the Security filter chain. It is quite straightforward to do it.
2. Demonstrate how to add a pre-authentication filter that allows a developer to run their applications locally without having to login every time they restart their apps. This filter, on the other hand, is added as a Security Filter and it works pretty much as the `AnonymousAuthenticationFilter`. 
I think another way to achieve this goal, but i have not tried it yet, is to rely on BasicAuthenticationFilter and configure the roles for the default user in the `application.yml` `security.rule.role: ADMIN` and rely on the browser to cache your user´s credentials. We would only have to activate the basic Authentication. It is worth trying this one.

To demonstrate goal 1 you just need to run the app as it is.
To demonstrate goal 2 though you need to activate the profile `preAuth`. The user, credential and roles are read from the `application.yml`.

Issues pending to be resolved:
- Management endpoint roles is not enforced. In other words, as long as the user is fully authenticated, I am allowed to access any endpoint. The role does not appear to be enforced.
