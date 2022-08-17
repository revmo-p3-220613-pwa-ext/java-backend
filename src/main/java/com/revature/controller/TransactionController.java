package com.revature.contoller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.revature.controller.Controller;
import com.revature.model.User;
import com.revature.service.TransactionService;
import io.javalin.Javalin;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.InvalidParameterException;
import java.util.Map;

public class TransactionController implements Controller {
    private TransactionService transactionService;

    public TransactionController() {
        this.transactionService = new TransactionService();
    }


    @Override
    public void mapEndpoints(Javalin app) {
        app.post("/account", ctx -> {
            HttpServletRequest req = ctx.req;

            HttpSession session = req.getSession();
            User myUser = (User) session.getAttribute("logged_in_user");

            ObjectMapper om = new ObjectMapper();
            Map<String, String> newTransaction = om.readValue(ctx.body(), Map.class);
            //DeviceWarranty newWarranty = ctx.bodyAsClass(DeviceWarranty.class);
            //newWarranty.setWarrantyRequester(myUser.getUsername());
//            Transaction addedTransaction = newTransaction;
//            addedTransaction.setTransactionId();
            try {
                ctx.json(transactionService.addTransactionById(newTransaction));
                ctx.status(201);
            } catch (InvalidParameterException e) {
//                ctx.json(e.getMessages());
                ctx.status(400);
            }

        });
    }
}


