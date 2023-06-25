package telran.java47.security.context;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

import telran.java47.security.model.User;
@Component
public class SecurityContextImpl implements SecurityContext {
	Map<String, User> context=new ConcurrentHashMap<>();

	@Override
	public User addUserSession(String sessionId, User user) {
		// TODO Auto-generated method stub
		return context.put(sessionId, user);
	}

	@Override
	public User removeUserSession(String sessionId) {
		// TODO Auto-generated method stub
		return context.remove(sessionId);
	}

	@Override
	public User getUserBySession(String sessionId) {
		// TODO Auto-generated method stub
		return context.get(sessionId);
	}

}
