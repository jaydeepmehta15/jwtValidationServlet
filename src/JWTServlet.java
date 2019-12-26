

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

/**
 * Servlet implementation class JWTServlet
 */
@WebServlet("/JWTServlet")
public class JWTServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public JWTServlet() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	/*
	 * protected void doGet(HttpServletRequest request, HttpServletResponse
	 * response) throws ServletException, IOException {
	 * 
	 * response.getWriter().append("Served at: ").append(request.getContextPath());
	 * }
	 */

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		
		String TokenString = request.getHeader("Authorization");
		
		String token = TokenString.substring(7);
		
		
		JWSObject jwt = null;
		
		try {
			jwt = JWSObject.parse(token);
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println(jwt.getHeader());
		System.out.println(jwt.getPayload().toString());
		
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
			    new DefaultJWTProcessor<>();
		
		JWKSource<SecurityContext> keySource =
			    new RemoteJWKSet<>(new URL("https://dev-624378.okta.com/oauth2/default/v1/keys"));
		
		JWSKeySelector<SecurityContext> keySelector =
			    new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keySource);
		
		jwtProcessor.setJWSKeySelector(keySelector);
		
		try {
			JWTClaimsSet claimsSet = jwtProcessor.process(token, null);
			System.out.println(claimsSet.toJSONObject());
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadJOSEException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JOSEException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		response.getWriter().append("Served at: ").append(jwt.getPayload().toString());
		
		
		
		
		
	}

}
