package com.revature;
import com.revature.contoller.TransactionController;
import com.revature.controller.Controller;
import io.javalin.Javalin;

public class main {
    public static void main(String[] args) {
        Javalin app = Javalin.create(javalinConfig -> {
            javalinConfig.enableCorsForAllOrigins();
        });

        Controller[] controllers = {new TransactionController()};

        for (int i = 0; i < controllers.length; i++) {
            controllers[i].mapEndpoints(app);
        }

        app.start(8080);
    }
}
