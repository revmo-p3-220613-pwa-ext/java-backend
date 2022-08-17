package com.revature.dao;
import com.revature.model.*;
import com.revature.utility.ConnectionUtility;
import kotlin.time.TimeSource;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class TransactionDao {
    public String addTransactionByRequestingId(Transaction transaction) throws SQLException {
        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("Insert INTO transactions (requester_id, sending_id, " +
                    "receiving_id, status_id, amount, desc_id, req_time) VALUES (?, ?, ?, ?, ?, ?, Now())");

            ps.setInt(1, transaction.getReceivingId());

            ps.setInt(2, transaction.getSendingId());
            ps.setInt(3, transaction.getReceivingId());
//            ps.setTimestamp(4, requesterId.getRequestTime());
            ps.setInt(4, transaction.getStatus_id());
            ps.setLong(5, transaction.getBalance());
            ps.setInt(6, transaction.getDescriptionId());


            return "Transaction Successful";

        }


    }

    public List<Transaction> getAllTransactions() throws SQLException {
        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("SELECT * FROM transactions");
            ResultSet rs = ps.executeQuery();
            List<Transaction> transactionsList = new ArrayList<>();
            while (rs.next()) {
                int transactionId = rs.getInt("id");
                int requesterId = rs.getInt("requester_id");
                int sendingId = rs.getInt("sending_id");
                int receivingId = rs.getInt("receiving_id");
                Timestamp reqTime = rs.getTimestamp("req_time");
                Timestamp resTime = rs.getTimestamp("res_time");
                boolean approve = rs.getBoolean("approved");
                long amount = rs.getLong("amount");
                int status_id = rs.getInt("status_id");
                int descriptionId = rs.getInt("desc_id");
                Transaction transaction = new Transaction(transactionId, requesterId,
                        sendingId, receivingId, reqTime, resTime, approve, status_id,
                        descriptionId, amount);
                transactionsList.add(transaction);
            }
            return transactionsList;
        }
    }
}
