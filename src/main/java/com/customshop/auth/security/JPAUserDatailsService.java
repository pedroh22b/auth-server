package com.customshop.auth.security;

import com.customshop.auth.model.UserRepository;
import com.customshop.auth.model.UserModel;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class JPAUserDatailsService implements UserDetailsService {

	@Autowired
    private  UserRepository userRepository;
	
	@Autowired
	private PasswordEncoder pass;
	
	public List<UserModel> getAllUsers(){
		return userRepository.findAll();
		
	}
	
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    	System.out.println(getAllUsers());
        List<UserModel> user = getAllUsers(); 
        UserModel userDef = new UserModel();
        for (UserModel userModel : user) {
			if(userModel.getEmail().equals(email)) {
				userDef = userModel;
			}
		}

        final var simpleGrantedAuthority = new SimpleGrantedAuthority("ROLE_" + userDef.getType().name());
        System.out.println("userDef: " + userDef.getCpf());
        System.out.println(List.of(simpleGrantedAuthority));
        System.out.println(pass.encode("root"));
        
        UserDetails userReturn = User.withUsername(userDef.getEmail()).password(userDef.getSenha()).authorities(List.of(simpleGrantedAuthority)).build();
        System.out.println(userReturn);
        return userReturn;
    }
    

}
