package com.revature.service;

import com.revature.dao.UserDao;
import com.revature.exception.InvalidParameterException;
import com.revature.model.User;
import com.revature.exception.InvalidLoginException;
import com.revature.utility.EmailUtility;
import io.github.cdimascio.dotenv.Dotenv;
import io.jsonwebtoken.Jwts;
import org.json.JSONObject;

import java.sql.SQLException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import java.util.List;

import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static junit.framework.Assert.assertTrue;

public class UserService {
    private UserDao userDao;
    private String firstName;
    private String lastName;
    private String email;

    private String password;
    private String phoneNumber;
    private String userRole;
    private String regexPattern;
    private UserService EmailValidation;


    public UserService(UserDao mockedObject) {
        userDao = mockedObject;
    }

    public UserService() {
        this.userDao = new UserDao();
    }
    public String addUser(Map<String, String> newUser)throws InvalidParameterException {
       User user = new User();
       InvalidParameterException exceptions = new InvalidParameterException();
       if (newUser.get("firstName") == null) {
           exceptions.addMessage("User must have a First Name");

       }
       if (newUser.get("lastName") == null) {
           exceptions.addMessage("User must have a Last Name");
       }
//       if (email == null) {
//           exceptions.addMessage("User must have an email");
//           throw exceptions;
//
//       }
//       if (phoneNumber == null) {
//           exceptions.addMessage("User must have a Phone Number");
//           throw exceptions;
//       }
       if (newUser.get("password") == null) {
           exceptions.addMessage("User must be assigned a Role");



       }
//          byte newpassword = isValidPassword(newUser.get("password"));

        if (exceptions.containsMessage()) {
            throw exceptions;
        }
        user.setFirstName(newUser.get("firstName"));
        user.setLastName(newUser.get("lastName"));
        user.setEmail(newUser.get("email"));
        user.setPhoneNumber(newUser.get("phoneNumber"));
        user.setPassword(newUser.get("password"));


        return userDao.addUser(user);
    }
//    public byte isValidPassword(String password)
//    {
//
//        // Regex to check valid password.
//        String regex = "^(?=.*[0-9])"
//                + "(?=.*[a-z])(?=.*[A-Z])"
//                + "(?=.*[@#$%^&+=])"
//                + "(?=\\S+$).{8,20}$";
//
//        // Compile the ReGex
//        Pattern p = Pattern.compile(regex);
//
//        // If the password is empty
//        // return false
//        if (password == null) {
//            return false;
//        }
//
//        // Pattern class contains matcher() method
//        // to find matching between given password
//        // and regular expression.
//        Matcher m = p.matcher(password);
//
//        // Return if the password
//        // matched the ReGex
//        return m.matches();
//    }
    public static boolean patternMatches(String email, String regexPattern) {
        return Pattern.compile(regexPattern)
                .matcher(email)
                .matches();
    }
    public void testUsingSimpleRegex() {
        email = "username@domain.com";
        regexPattern = "^(.+)@(\\S+)$";
        assertTrue(patternMatches(email, regexPattern));
    }

    public boolean getUserEmailByEmail(String email) {
        return userDao.getUserEmailByEmail(email);
    }

    public void updatePassword(String password, String token) {
        userDao.updatePassword(password, token);
    }

    public User getUserByInputEmail(String inputEmail) {
        return userDao.getUserByInputEmail(inputEmail);
    }

    public boolean sendToken(String token, int userId) {
        return userDao.sendToken(token, userId);
    }

    public boolean validateToken(String token) {
        return userDao.validateToken(token);
    }

    public void deleteToken(String token) {
        userDao.deleteToken(token);
    }

    public User login(String email, String password) throws SQLException, InvalidLoginException {
        User user = userDao.getUserByEmailAndPassword(email, password);

        if (user == null) {
            throw new InvalidLoginException("Invalid email and/or password");
        }
        return user;
    }


    public User getUserByEmail(String email) {


        return userDao.getUserByEmail(email);

    }


    public void updateInfo(Map<String, String> newInfo, int userId, String oldEmail) throws InvalidParameterException {
        InvalidParameterException exceptions = new InvalidParameterException();

        String newFirstName = newInfo.get("firstName");
        String newLastName = newInfo.get("lastName");

        String newPhone = newInfo.get("phone");
        User oldUser = userDao.getUserByEmail(oldEmail);
        if (userId != oldUser.getUserId()) {
            exceptions.addMessage("User Id does not match our records.");
            throw exceptions;
        }


        if (!Objects.equals(newFirstName, oldUser.getFirstName())) {
            userDao.updateFirstName(userId, newFirstName);
        }
        if (!Objects.equals(newLastName, oldUser.getLastName())) {
            userDao.updateLastName(userId, newLastName);

        }
        if (!Objects.equals(newPhone, oldUser.getPhoneNumber())) {
            userDao.updatephone(userId, newPhone);
        }

    }


    public String getRequesteeByTransactionId(int transactionId) {
        return userDao.getRequesteeEmailByTransactionId(transactionId);
    }

    public List<String> getReceiverByTransactionId(int transactionId) {
        return userDao.getReceiverEmailByTransactionId(transactionId);
    }

    public boolean forgetPassword(JSONObject inputEmail) {
        try {

            //Check if email is in the database
            if (userDao.getUserEmailByEmail(inputEmail.getString("email"))) {

                //return user Object based on email found
                User currUser = userDao.getUserByInputEmail(inputEmail.getString("email"));

                //Create web Token based on values with expiration
                String jwtToken = Jwts.builder().claim("last_name", currUser.getLastName()).claim("userId", currUser.getUserId()).claim("email", currUser.getEmail()).setSubject(currUser.getFirstName()).setId(UUID.randomUUID().toString()).setIssuedAt(Date.from(Instant.now())).setExpiration(Date.from(Instant.now().plus(5L, ChronoUnit.MINUTES))).compact();

                //Send Token to Database
                userDao.sendToken(jwtToken, currUser.getUserId());
                Dotenv dotenv = Dotenv.load();
                //Create URL and send email with reset URL
                String frontendUrl = dotenv.get("FRONTEND_HOST");
                String addressUrl = frontendUrl + "/resetpassword?token=" + jwtToken;
                int status = EmailUtility.email(inputEmail.getString("email"), "Reset your RevMo password", addressUrl);
                if (status == 202) {
                    return true;
                } else {
                    throw new RuntimeException("The email pertaining to the account has been sent an email. Please check email for reset link.");
                }
            } else {
                throw new RuntimeException("The email pertaining to the account has been sent an email. Please check email for reset link.");
            }
        } catch (Exception e) {
            throw new RuntimeException("The email pertaining to the account has been sent an email. Please check email for reset link.");
        }
    }

    public User getUserByUserId(int uId) {
        return userDao.getUserByUserId(uId);
    }

}

