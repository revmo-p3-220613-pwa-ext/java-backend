package com.revature.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.util.JSONPObject;
import com.revature.dao.UserDao;
import com.revature.exception.InvalidParameterException;

import com.revature.model.User;
import com.revature.utility.EmailUtility;
import io.jsonwebtoken.Jwts;

import java.lang.Exception;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.UUID;


import com.revature.exception.InvalidLoginException;
import com.revature.service.UserService;
import io.javalin.Javalin;
import org.json.JSONObject;

import java.sql.SQLException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.revature.model.Account;
import com.revature.service.AccountService;

import java.util.List;


public class UserController implements Controller {
    private UserService userService;
    private AccountService accountService;

    public UserController() {
        this.userService = new UserService();
        this.accountService = new AccountService();
    }

    @Override
    public void mapEndpoints(Javalin app) {

        app.post("/login", ctx -> {
            User user = ctx.bodyAsClass(User.class);

            String email = user.getEmail();
            String pass = user.getPassword();
            try {
                User loggedInUser = userService.login(email, pass);

                HttpServletRequest req = ctx.req;
                HttpSession session = req.getSession();
                session.setAttribute("userId", loggedInUser.getUserId());
                session.setAttribute("email", loggedInUser.getEmail());
                session.setAttribute("userRole", loggedInUser.getUserRole());

                ctx.json(loggedInUser);
            } catch (InvalidLoginException | SQLException e) {
                ctx.result(e.getMessage());
                ctx.status(400);
            }

        });
        app.post("/registration", ctx -> {
            ObjectMapper om = new ObjectMapper();
            Map<String, String> newUser = om.readValue(ctx.body(), Map.class);
            try {
            ctx.json(userService.addUser(newUser));
                ctx.status(201);
            }
            catch (InvalidParameterException e) {
                ctx.result(e.getMessage());
                ctx.status(400);
            }
            User user = ctx.bodyAsClass(User.class);

            HttpServletRequest req = ctx.req;
            HttpSession session = req.getSession();




        });

        app.post("/logout", ctx -> {
//            System.out.println("logout");

            HttpServletRequest req = ctx.req;
            HttpSession session = req.getSession();
            ctx.result("Successfully logged out");
            session.invalidate();
            ctx.status(201);
        });

        app.get("/logged-in-user", ctx -> {
            HttpServletRequest req = ctx.req;

            HttpSession session = req.getSession();
            User myUser = (User) session.getAttribute("logged_in_user");

            if (myUser == null) {
                ctx.result("You are not logged in!");
                ctx.status(404);
            } else {

            }

        });

        // returns currently logged-in user's info
        app.get("/user", ctx -> {
            HttpServletRequest req = ctx.req;
            HttpSession session = req.getSession();
            String email = (String) session.getAttribute("email");


            if (email == null) {


                ctx.result("You are not logged in!");
                ctx.status(404);
            } else {
                User myUser = userService.getUserByEmail(email);
                List<Account> userAccounts = accountService.getAccountsByEmail(email);

                myUser.setAccounts(userAccounts);

                ctx.json(myUser);
                ctx.status(200);
            }
        });

        app.post("/user", ctx -> {
            HttpServletRequest req = ctx.req;
            HttpSession session = req.getSession();
            String email = (String) session.getAttribute("email");

            if (email == null) {
                ctx.result("You are not logged in!");
                ctx.status(404);
            } else {
                ObjectMapper om = new ObjectMapper();
                Map<String, String> newInfo = om.readValue(ctx.body(), Map.class);
                try {
                    userService.updateInfo(newInfo, (Integer) session.getAttribute("userId"), email);
                    ctx.status(201);
                } catch (InvalidParameterException e) {
                    ctx.json(e.getMessages());
                    ctx.status(400);
                }

            }
        });

        app.put("/resetpassword", ctx -> {

            //Try and Catch for error
            try {
                //retrieve token from inputted parameter
                String token = ctx.req.getParameter("token");

                //Decode token to check expiration
                DecodedJWT jwt = JWT.decode(token);
                //If valid token not expired validate if correct
                if (jwt.getExpiresAt().before(new Date())) {
                    ctx.status(404);
                    throw new RuntimeException("Reset Link Expired. Please try again");
                } else {
                    boolean validateToken = userService.validateToken(token); // we need to write a code to verify the token validity
                    if (validateToken) {
                        //get new password from json input
                        JSONObject newPassword = new JSONObject(ctx.body());
                        //Update password in Database and delete token
                        userService.updatePassword(newPassword.getString("newpassword"), token);
                        userService.deleteToken(token);
                        // redirect user to setup a new password page
                    } else {
                        ctx.status(404);
                        throw new RuntimeException("OOPS something went wrong. Reset Link Expired");
                        // return user a message with invalid token
                    }
                }
            } catch (Exception e) {
                ctx.status(404);
                throw new RuntimeException("Reset Link Expired. Please try again");
            }
        });

        app.post("/forgotpassword", ctx -> {
            //String email="";
            //Create JSONObject with inputted json value
            try {
                JSONObject inputEmail = new JSONObject(ctx.body());
                if (inputEmail.getString("email").equals("")) {
                    ctx.result("Please enter the email!");
                    ctx.status(404);
                    throw new RuntimeException("The email pertaining to the account has been sent an email. Please check email for reset link.");
                }
                //Check if email is in the database
                if (userService.getUserEmailByEmail(inputEmail.getString("email"))) {
                    //Create new user Object
                    User currUser = new User();

                    //return user Object based on email found
                    currUser = userService.getUserByInputEmail(inputEmail.getString("email"));

                    //Create web Token based on values with expiration
                    String jwtToken = Jwts.builder().claim("last_name", currUser.getLastName()).claim("userId", currUser.getUserId()).claim("email", currUser.getEmail()).setSubject(currUser.getFirstName()).setId(UUID.randomUUID().toString()).setIssuedAt(Date.from(Instant.now())).setExpiration(Date.from(Instant.now().plus(5L, ChronoUnit.MINUTES))).compact();

                    //Send Token to Database
                    userService.sendToken(jwtToken, currUser.getUserId());

//                    System.out.println(jwtToken);

                    //Create URL and send email with reset URL
                    String addressUrl =  "http://localhost:5051/resetpassword?token="+jwtToken;
                    int status = EmailUtility.email(inputEmail.getString("email"), "Reset your RevMo password", addressUrl);
                    if (status == 202) {
                        System.out.println("Please Check Your Email!");
                    } else {
                        ctx.status(404);
                        throw new RuntimeException("The email pertaining to the account has been sent an email. Please check email for reset link.");
                    }

                } else {
                    boolean status = userService.forgetPassword(inputEmail);
                    if ( status ){
                        ctx.status(202);
                    } else {
                        ctx.status(403);
                    }
                }
            }catch (Exception e) {
                ctx.json(e.getMessage());
                ctx.status(400);
            }
        });


    }
}
