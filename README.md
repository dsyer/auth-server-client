Sample application that is both an OAuth2 authorization server and a client of the same server.

Spring Boot doesn't support this pattern as an autoconfiguration, and that's reasonable because it's not so common. Where it often comes into play is when the auth server is also a gateway to other backend services that want to be authenticated using the tokens issued by the server. Hence this app is also a Zuul gateway (with `@EnableZuulProxy`). It uses the `spring-cloud-starter-oauth2` to set up token relay between the authenticated user and backend services.

How does it work? Essentially it re-creates the pieces that are autoconfigured by Spring Boot when a user adds `@EnableOAuth2Sso`. Spring Boot offers 3 options for `ResourceServerTokenServices` implementations that work with `@EnableOAuth2Sso` (to decode tokens and extract user info for the authentication), but none of them is the "native" implementation that is provided by an embedded auth server. The custom configuration in this app is just a few lines that grabs the native `ResourceServerTokenServices` and injects it into a filter. The details are all in the `Sso` class in the top level `DemoApplication`.

```java
@Configuration
@EnableOAuth2Client
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
class Sso extends WebSecurityConfigurerAdapter {

	@Autowired
	private OAuth2ClientContext oauth2ClientContext;
	@Autowired
	private AuthorizationCodeResourceDetails client;
	@Autowired
	private AuthorizationServerTokenServices tokenServices;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.requestMatcher(
				new NegatedRequestMatcher(new AntPathRequestMatcher("/oauth/**")))
				.authorizeRequests().anyRequest().authenticated().and()
				.exceptionHandling()
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")).and()
				.logout().logoutSuccessUrl("/").permitAll().and().csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
				.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
		;
	}

	private Filter ssoFilter() {
		OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(
				"/login");
		OAuth2RestTemplate template = new OAuth2RestTemplate(client,
				oauth2ClientContext);
		filter.setRestTemplate(template);
		filter.setTokenServices((ResourceServerTokenServices) tokenServices);
		return filter;
	}

}
```

The app runs on port 8080. Test it by visiting `/user` (a local endpoint) or `/api/example` (a Zuul route). User authentication for the OAuth2 token generation is the default Spring Boot basic HTTP. It is configured with a user name and password `(user,password)`. Your browser will remember those credentials, so don't expect to have to enter them more than once, unless you use an incongnito browser window.
