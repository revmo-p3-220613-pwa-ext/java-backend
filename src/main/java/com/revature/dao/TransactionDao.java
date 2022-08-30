package com.revature.dao;

import com.revature.model.*;
import com.revature.utility.ConnectionUtility;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class TransactionDao {
    public String moveAmountBetweenAccounts(Transaction transaction) {
        try (Connection con = ConnectionUtility.createConnection()) {
            con.setAutoCommit(false);
            System.out.println(transaction);

            try (
                    PreparedStatement ps = con.prepareStatement("INSERT INTO transactions (requester_id, " +
                            "sending_id,receiving_id, req_time, res_time, status_id, amount, desc_id, receiving_email) " +
                            "VALUES(?, ?, ?, Now(), Now(), 2, ?, 2, ?)");
                    PreparedStatement ps1 = con.prepareStatement("UPDATE accounts SET balance = balance - ? " +
                            "WHERE id = ? ");
                    PreparedStatement ps2 = con.prepareStatement("UPDATE accounts SET balance = balance + ? " +
                            "WHERE id = ? ");
            ) {
                // Create insert statement
                ps.setInt(1, transaction.getRequesterId());
                ps.setInt(2, transaction.getSendingId());
                ps.setInt(3, transaction.getReceivingId());
                ps.setLong(4, transaction.getAmount());
                ps.setString(5, transaction.getReceivingEmail());
                ps.executeUpdate();
                //change balance for account moving amount out of
                ps1.setLong(1, transaction.getAmount());
                ps1.setInt(2, transaction.getSendingId());
                ps1.executeUpdate();
                // change balance for account receiving amount
                ps2.setLong(1, transaction.getAmount());
                ps2.setInt(2, transaction.getReceivingId());
                ps2.executeUpdate();
                con.commit();
            } catch (SQLException e) {
//                System.out.println(e);
                try {
                    // Roll back transaction
                    con.rollback();
                    return "Transaction is being rolled back.";
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return "Transaction Successful";
    }

    public String storeRequest(Transaction transaction) {
        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("INSERT INTO transactions (requester_id, " +
                    "sending_id,receiving_id, req_time, status_id, amount, desc_id, receiving_email) " +
                    "VALUES(?, ?, ?, Now(),1, ?, 4,?) RETURNING *");
//            Create insert statement
            ps.setInt(1, transaction.getRequesterId());
            ps.setInt(2, transaction.getSendingId());
            ps.setInt(3, transaction.getReceivingId());
            ps.setLong(4, transaction.getAmount());
            ps.setString(5, transaction.getReceivingEmail());
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return "Transaction Successful";
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return "Transaction Failed!";
    }

    public List<Transaction> getAllTransactions() throws SQLException {
        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("SELECT t.id, t.requester_id, t.sending_id, t.receiving_id, t.req_time, t.res_time, t.amount, t.receiving_email,  concat_ws(' ', u.first_name,u.last_name) as initiated_by, st.type_name, td.description " +
                    "FROM transactions t " +
                    "JOIN users u ON t.requester_id = u.id " +
                    "JOIN status_types st ON t.status_id  = st.id " +
                    "JOIN transaction_descriptions td ON t.desc_id  = td.id;");

            ResultSet rs = ps.executeQuery();
            List<Transaction> transactionsList = new ArrayList<>();
            while (rs.next()) {
                int transactionId = rs.getInt("id");
                int requesterId = rs.getInt("requester_id");
                int sendingId = rs.getInt("sending_id");
                int receivingId = rs.getInt("receiving_id");
                Timestamp reqTime = rs.getTimestamp("req_time");
                Timestamp resTime = rs.getTimestamp("res_time");
                long amount = rs.getLong("amount");
                String receivingEmail = rs.getString("receiving_email");
                String initiatedBy = rs.getString("initiated_by");
                String typeName = rs.getString("type_name");
                String description = rs.getString("description");
                Transaction transaction = new Transaction(transactionId, requesterId,
                        sendingId, receivingId, reqTime, resTime, receivingEmail,
                        initiatedBy, typeName, description, amount);
                transactionsList.add(transaction);
            }
            return transactionsList;
        }
    }

    public List<Transaction> getAllTransactions(int aid) throws SQLException {
        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("SELECT t.id, t.requester_id, t.sending_id, t.receiving_id, t.req_time, t.res_time, t.amount, t.receiving_email,  concat_ws(' ', u.first_name,u.last_name) as initiated_by, st.type_name, td.description " +
                    "FROM transactions t " +
                    "JOIN users u ON t.requester_id = u.id " +
                    "JOIN status_types st ON t.status_id  = st.id " +
                    "JOIN transaction_descriptions td ON t.desc_id  = td.id " +
                    "WHERE t.sending_id = ? OR t.receiving_id = ?" +
                    "ORDER BY res_time DESC");

            ps.setInt(1, aid);
            ps.setInt(2, aid);

            ResultSet rs = ps.executeQuery();
            List<Transaction> transactionsList = new ArrayList<>();
            while (rs.next()) {
                int transactionId = rs.getInt("id");
                int requesterId = rs.getInt("requester_id");
                int sendingId = rs.getInt("sending_id");
                int receivingId = rs.getInt("receiving_id");
                Timestamp reqTime = rs.getTimestamp("req_time");
                Timestamp resTime = rs.getTimestamp("res_time");
                long amount = rs.getLong("amount");
                String receivingEmail = rs.getString("receiving_email");
                String initiatedBy = rs.getString("initiated_by");
                String typeName = rs.getString("type_name");
                String description = rs.getString("description");
                Transaction transaction = new Transaction(transactionId, requesterId,
                        sendingId, receivingId, reqTime, resTime, receivingEmail,
                        initiatedBy, typeName, description, amount);
                transactionsList.add(transaction);
            }
            return transactionsList;
        }
    }

    public List<Transaction> getAllTransactionsByRequesterId(int requestId) throws SQLException {
        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("SELECT t.id, t.requester_id, t.sending_id, t.receiving_id, t.req_time, t.res_time, t.amount, t.receiving_email,  concat_ws(' ', u.first_name,u.last_name) as initiated_by, st.type_name, td.description " +
                    "FROM transactions t " +
                    "JOIN users u ON t.requester_id = u.id " +
                    "JOIN status_types st ON t.status_id  = st.id " +
                    "JOIN transaction_descriptions td ON t.desc_id  = td.id " +
                    "WHERE t.requester_id  = ?");
            ps.setInt(1, requestId);
            ResultSet rs = ps.executeQuery();
            List<Transaction> transactionsList = new ArrayList<>();
            while (rs.next()) {
                int transactionId = rs.getInt("id");
                int requesterId = rs.getInt("requester_id");
                int sendingId = rs.getInt("sending_id");
                int receivingId = rs.getInt("receiving_id");
                Timestamp reqTime = rs.getTimestamp("req_time");
                Timestamp resTime = rs.getTimestamp("res_time");
                long amount = rs.getLong("amount");
                String receivingEmail = rs.getString("receiving_email");
                String initiatedBy = rs.getString("initiated_by");
                String typeName = rs.getString("type_name");
                String description = rs.getString("description");
                Transaction transaction = new Transaction(transactionId, requesterId,
                        sendingId, receivingId, reqTime, resTime, receivingEmail,
                        initiatedBy, typeName, description, amount);
                transactionsList.add(transaction);
            }
            return transactionsList;
        }
    }

    public List<Transaction> getAllTransactionsBySenderId(int senderId) throws SQLException {
        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("SELECT t.id, t.requester_id, t.sending_id, t.receiving_id, t.req_time, t.res_time, t.amount, t.receiving_email,  concat_ws(' ', u.first_name,u.last_name) as initiated_by, st.type_name, td.description" +
                    " FROM transactions t" +
                    " JOIN users u ON t.requester_id = u.id" +
                    " JOIN status_types st ON t.status_id  = st.id" +
                    " JOIN transaction_descriptions td ON t.desc_id  = td.id" +
                    " WHERE t.sending_id  = ?");
            ps.setInt(1, senderId);
            ResultSet rs = ps.executeQuery();
            List<Transaction> transactionsList = new ArrayList<>();
            while (rs.next()) {
                int transactionId = rs.getInt("id");
                int requesterId = rs.getInt("requester_id");
                int sendingId = rs.getInt("sending_id");
                int receivingId = rs.getInt("receiving_id");
                Timestamp reqTime = rs.getTimestamp("req_time");
                Timestamp resTime = rs.getTimestamp("res_time");
                long amount = rs.getLong("amount");
                String receivingEmail = rs.getString("receiving_email");
                String initiatedBy = rs.getString("initiated_by");
                String typeName = rs.getString("type_name");
                String description = rs.getString("description");
                Transaction transaction = new Transaction(transactionId, requesterId,
                        sendingId, receivingId, reqTime, resTime, receivingEmail,
                        initiatedBy, typeName, description, amount);
                transactionsList.add(transaction);
            }
            return transactionsList;
        }
    }

    public List<Transaction> getAllTransactionsByRecievingId(int receiveId) throws SQLException {
        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("SELECT t.id, t.requester_id, t.sending_id, t.receiving_id, t.req_time, t.res_time, t.amount, t.receiving_email,  concat_ws(' ', u.first_name,u.last_name) as initiated_by, st.type_name, td.description" +
                    " FROM transactions t" +
                    " JOIN users u ON t.requester_id = u.id" +
                    " JOIN status_types st ON t.status_id  = st.id" +
                    " JOIN transaction_descriptions td ON t.desc_id  = td.id" +
                    " WHERE t.receiving_id  = ?");
            ps.setInt(1, receiveId);
            ResultSet rs = ps.executeQuery();
            List<Transaction> transactionsList = new ArrayList<>();
            while (rs.next()) {
                int transactionId = rs.getInt("id");
                int requesterId = rs.getInt("requester_id");
                int sendingId = rs.getInt("sending_id");
                int receivingId = rs.getInt("receiving_id");
                Timestamp reqTime = rs.getTimestamp("req_time");
                Timestamp resTime = rs.getTimestamp("res_time");
                long amount = rs.getLong("amount");
                String receivingEmail = rs.getString("receiving_email");
                String initiatedBy = rs.getString("initiated_by");
                String typeName = rs.getString("type_name");
                String description = rs.getString("description");
                Transaction transaction = new Transaction(transactionId, requesterId,
                        sendingId, receivingId, reqTime, resTime, receivingEmail,
                        initiatedBy, typeName, description, amount);
                transactionsList.add(transaction);
            }
            return transactionsList;
        }
    }

    public List<Transaction> getAllOutgoingTransactionsByStatusName(String statusName, int aId) throws SQLException {
        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("SELECT t.id, t.requester_id, t.sending_id, t.receiving_id, t.req_time, t.res_time, t.amount, t.receiving_email,  concat_ws(' ', u.first_name,u.last_name) as initiated_by, st.type_name, td.description" +
                    " FROM transactions t" +
                    " JOIN users u ON t.requester_id = u.id" +
                    " JOIN status_types st ON t.status_id  = st.id" +
                    " JOIN transaction_descriptions td ON t.desc_id  = td.id" +
                    " WHERE st.type_name  = ? AND t.sending_id = ? ");
            ps.setString(1, statusName);
            ps.setInt(2, aId);
            ResultSet rs = ps.executeQuery();
            List<Transaction> transactionsList = new ArrayList<>();
            while (rs.next()) {
                int transactionId = rs.getInt("id");
                int requesterId = rs.getInt("requester_id");
                int sendingId = rs.getInt("sending_id");
                int receivingId = rs.getInt("receiving_id");
                Timestamp reqTime = rs.getTimestamp("req_time");
                Timestamp resTime = rs.getTimestamp("res_time");
                long amount = rs.getLong("amount");
                String receivingEmail = rs.getString("receiving_email");
                String initiatedBy = rs.getString("initiated_by");
                String typeName = rs.getString("type_name");
                String description = rs.getString("description");
                Transaction transaction = new Transaction(transactionId, requesterId,
                        sendingId, receivingId, reqTime, resTime, receivingEmail,
                        initiatedBy, typeName, description, amount);
                transactionsList.add(transaction);
            }
            return transactionsList;
        }
    }


    public List<Transaction> getAllIncomingTransactionsByStatusName(String statusName, int aId) throws SQLException {
        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("SELECT t.id, t.requester_id, t.sending_id, t.receiving_id, t.req_time, t.res_time, t.amount, t.receiving_email,  concat_ws(' ', u.first_name,u.last_name) as initiated_by, st.type_name, td.description" +
                    " FROM transactions t" +
                    " JOIN users u ON t.requester_id = u.id" +
                    " JOIN status_types st ON t.status_id  = st.id" +
                    " JOIN transaction_descriptions td ON t.desc_id  = td.id" +
                    " WHERE st.type_name  = ? AND t.receiving_id = ? ");
            ps.setString(1, statusName);
            ps.setInt(2, aId);
            ResultSet rs = ps.executeQuery();
            List<Transaction> transactionsList = new ArrayList<>();
            while (rs.next()) {
                int transactionId = rs.getInt("id");
                int requesterId = rs.getInt("requester_id");
                int sendingId = rs.getInt("sending_id");
                int receivingId = rs.getInt("receiving_id");
                Timestamp reqTime = rs.getTimestamp("req_time");
                Timestamp resTime = rs.getTimestamp("res_time");
                long amount = rs.getLong("amount");
                String receivingEmail = rs.getString("receiving_email");
                String initiatedBy = rs.getString("initiated_by");
                String typeName = rs.getString("type_name");
                String description = rs.getString("description");
                Transaction transaction = new Transaction(transactionId, requesterId,
                        sendingId, receivingId, reqTime, resTime, receivingEmail,
                        initiatedBy, typeName, description, amount);
                transactionsList.add(transaction);
            }
            return transactionsList;
        }
    }

    public List<Transaction> getAllTransactionsByDescription(String desc) throws SQLException {
        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("SELECT t.id, t.requester_id, t.sending_id, t.receiving_id, t.req_time, t.res_time, t.amount, t.receiving_email,  concat_ws(' ', u.first_name,u.last_name) as initiated_by, st.type_name, td.description" +
                    " FROM transactions t" +
                    " JOIN users u ON t.requester_id = u.id" +
                    " JOIN status_types st ON t.status_id  = st.id" +
                    " JOIN transaction_descriptions td ON t.desc_id  = td.id" +
                    " WHERE td.description  = ?");
            ps.setString(1, desc);
            ResultSet rs = ps.executeQuery();
            List<Transaction> transactionsList = new ArrayList<>();
            while (rs.next()) {
                int transactionId = rs.getInt("id");
                int requesterId = rs.getInt("requester_id");
                int sendingId = rs.getInt("sending_id");
                int receivingId = rs.getInt("receiving_id");
                Timestamp reqTime = rs.getTimestamp("req_time");
                Timestamp resTime = rs.getTimestamp("res_time");
                long amount = rs.getLong("amount");
                String receivingEmail = rs.getString("receiving_email");
                String initiatedBy = rs.getString("initiated_by");
                String typeName = rs.getString("type_name");
                String description = rs.getString("description");
                Transaction transaction = new Transaction(transactionId, requesterId,
                        sendingId, receivingId, reqTime, resTime, receivingEmail,
                        initiatedBy, typeName, description, amount);
                transactionsList.add(transaction);
            }
            return transactionsList;
        }
    }

//    public Transaction sendMoneyRequest(Transaction transaction) throws SQLException {
//        try (Connection con = ConnectionUtility.createConnection()) {
//            con.setAutoCommit(false);
//            try (
//                    PreparedStatement ps = con.prepareStatement("INSERT INTO transactions (requester_id, " +
//                            "sending_id,receiving_id, req_time, status_id, amount, desc_id, receiving_email) " +
//                            "VALUES(?, ?, ?, Now(),?, ?, ?,?) RETURNING *");
//            ) {
//                ps.setInt(1, transaction.getRequesterId());
//                ps.setInt(2, transaction.getSendingId());
//                ps.setInt(3, transaction.getReceivingId());
//                ps.setInt(4, transaction.getStatusId());
//                ps.setLong(5, transaction.getAmount());
//                ps.setInt(6, transaction.getDescriptionId());
//                ps.setString(7, transaction.getReceivingEmail());
//                ps.executeUpdate();
//                ResultSet rs = ps.executeQuery();
//                while (rs.next()) {
//                    int transactionId = rs.getInt("id");
//                    int requesterId = rs.getInt("requester_id");
//                    int sendingId = rs.getInt("sending_id");
//                    int receivingId = rs.getInt("receiving_id");
//                    Timestamp reqTime = rs.getTimestamp("req_time");
//                    long amount = rs.getLong("amount");
//                    String receivingEmail = rs.getString("receiving_email");
//                    String initiatedBy = rs.getString("initiated_by");
//                    String typeName = rs.getString("type_name");
//                    String description = rs.getString("description");
//                    Transaction trx = new Transaction(transactionId, requesterId,
//                            sendingId, receivingId, reqTime, receivingEmail,
//                            initiatedBy, typeName, description, amount);
//                    return trx;
//                }
//
//            } catch (SQLException e) {
//                System.out.println(e);
//            }
//            return null;
//        }
//}
            /*
            This method will initiate a money transfer request. The request will then need to be approved by the person
            who would be transferring money to the requester.
             */

    public String completeRequestDenied(Transaction t) {
        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("UPDATE transactions SET status_id = 3, res_time = Now() " +
                    "WHERE id = ? RETURNING *");
            ps.setInt(1, t.getTransactionId());
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return "Request successfully denied.";
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return "Transaction update failed.";
    }

    public String cancelTransaction() throws SQLException {
        /*
        This method will cancel a transaction if it has not been approved OR denied.
         */
        return null;
    }


    public Object completeRequestApproved(Transaction transaction) {
        try (Connection con = ConnectionUtility.createConnection()) {
            con.setAutoCommit(false);

            try (
                    PreparedStatement ps = con.prepareStatement("UPDATE transactions SET status_id = 2,  " +
                            " res_time = Now() WHERE id = ? RETURNING *");
                    PreparedStatement ps1 = con.prepareStatement("UPDATE accounts SET balance = balance - ? " +
                            "WHERE id = ? ");
                    PreparedStatement ps2 = con.prepareStatement("UPDATE accounts SET balance = balance + ? " +
                            "WHERE id = ? ");
            ) {
                int sendingId = 0, receivingId = 0;
                long amount = 0L;
                // Update transaction record
                ps.setInt(1, transaction.getTransactionId());
                ResultSet rs = ps.executeQuery();
                if (rs.next()) {
                    sendingId = rs.getInt("sending_id");
                    receivingId = rs.getInt("receiving_id");
                    amount = rs.getLong("amount");
                }
                //change balance for account moving amount out of
                ps1.setLong(1, amount);
                ps1.setInt(2, sendingId);
                ps1.executeUpdate();
                // change balance for account receiving amount
                ps2.setLong(1, amount);
                ps2.setInt(2, receivingId);
                ps2.executeUpdate();
                con.commit();
            } catch (SQLException e) {
//                System.out.println(e);
                try {
                    // Roll back transaction
                    con.rollback();
                    return "Transaction is being rolled back.";
                } catch (Exception ex) {
//                    ex.printStackTrace();
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return "Transaction Successfully Approved and Executed";
    }

    public Long monthlyAccountIncome(int uId, int aId, int month, int year) {
        String mon = "";
        if (month < 10) {
            mon = "0" + month;
        } else {
            mon = "" + month;
        }
        String timestampMonth = "" + year + "-" + mon + "-01 00:00:00.000";
        String timestampYear = "" + year + "-01-01 00:00:00.000";
        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("SELECT  SUM(t.amount) AS monthly_income, " +
                    "DATE_TRUNC('month', t.res_time) as mon, DATE_TRUNC('year', t.res_time) as yyyy\n " +
                    "\tFROM transactions t \n " +
                    "\tWHERE t.receiving_id = ? AND DATE_TRUNC('month', t.res_time) = ?::TIMESTAMP AND " +
                    "DATE_TRUNC('year', t.res_time) = ?::TIMESTAMP\n AND t.status_id = 2 AND " +
                    "t.sending_id NOT IN( " +
                    "\t\tSELECT uwa .account_id\n " +
                    "\t\t\tFROM users_with_accounts uwa\n " +
                    "\t\t\tWHERE uwa.user_id = ? " +
                    " ) " +
                    "\tGROUP BY DATE_TRUNC('month', t.res_time), DATE_TRUNC('year', t.res_time)");
            ps.setInt(1, aId);
            ps.setString(2, timestampMonth);
            ps.setString(3, timestampYear);
            ps.setInt(4, uId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return rs.getLong("monthly_income");
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return 0L;

    }

    public Long allTimeAccountIncome(int uId, int aId) {

        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("SELECT  SUM(t.amount) AS allTime_income " +
                    "\tFROM transactions t \n " +
                    "\tWHERE t.receiving_id = ?  AND t.status_id = 2 AND " +
                    "t.sending_id NOT IN( " +
                    "\t\tSELECT uwa .account_id\n " +
                    "\t\t\tFROM users_with_accounts uwa\n " +
                    "\t\t\tWHERE uwa.user_id = ? " +
                    " ) ");
            ps.setInt(1, aId);
            ps.setInt(2, uId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return rs.getLong("allTime_income");
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return 0L;

    }

    public String transferBetweenAccounts(Transaction transaction) {
        try (Connection con = ConnectionUtility.createConnection()) {
            con.setAutoCommit(false);

            try (
                    PreparedStatement ps = con.prepareStatement("INSERT INTO transactions (requester_id, " +
                            "sending_id,receiving_id, req_time, res_time, status_id, amount, desc_id, receiving_email) " +
                            "VALUES(?, ?, ?, Now(), Now(),2, ?, 2, ?)");
                    PreparedStatement ps1 = con.prepareStatement("UPDATE accounts SET balance = balance - ? " +
                            "WHERE id = ? ");
                    PreparedStatement ps2 = con.prepareStatement("UPDATE accounts SET balance = balance + ? " +
                            "WHERE id = ? ");
            ) {
                // Create insert statement
                ps.setInt(1, transaction.getRequesterId());
                ps.setInt(2, transaction.getSendingId());
                ps.setInt(3, transaction.getReceivingId());
                ps.setLong(4, transaction.getAmount());
                ps.setString(5, transaction.getReceivingEmail());
                ps.executeUpdate();
                //change balance for account moving amount out of
                ps1.setLong(1, transaction.getAmount());
                ps1.setInt(2, transaction.getSendingId());
                ps1.executeUpdate();
                // change balance for account receiving amount
                ps2.setLong(1, transaction.getAmount());
                ps2.setInt(2, transaction.getReceivingId());
                ps2.executeUpdate();
                con.commit();

            } catch (SQLException e) {
                System.out.println(e);
                try {
                    // Roll back transaction
                    con.rollback();
                    return "Transaction is being rolled back.";
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return "Transaction Successful";
    }

    public int getCurrentMonth() {
        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("SELECT EXTRACT(MONTH FROM Now()) cur_month");
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return rs.getInt("cur_month");
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return -1;
    }

    public int getCurrentYear() {
        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("SELECT EXTRACT(YEAR FROM Now()) as cur_year");
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return rs.getInt("cur_year");
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return -1;
    }

    public Long monthlyUserIncome(int uId, int month, int year) {
        String mon = "";
        if (month < 10) {
            mon = "0" + month;
        } else {
            mon = "" + month;
        }
        String timestampMonth = "" + year + "-" + mon + "-01 00:00:00.000";
        String timestampYear = "" + year + "-01-01 00:00:00.000";
        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("SELECT  SUM(t.amount) AS monthly_income, " +
                    "DATE_TRUNC('month', t.res_time) as mon, DATE_TRUNC('year', t.res_time) as yyyy\n " +
                    "\tFROM transactions t \n " +
                    "\tWHERE t.receiving_id IN(" +
                    "SELECT uwa .account_id " +
                    "FROM users_with_accounts uwa " +
                    "WHERE uwa.user_id = ? " +
                    ") AND DATE_TRUNC('month', t.res_time) = ?::TIMESTAMP AND DATE_TRUNC('year', t.res_time) = ?::TIMESTAMP\n " +
                    "AND t.status_id = 2 AND t.sending_id NOT IN(\n " +
                    "\t\tSELECT uwa .account_id\n " +
                    "\t\t\tFROM users_with_accounts uwa\n " +
                    "\t\t\tWHERE uwa.user_id = ?) " +
                    "\tGROUP BY DATE_TRUNC('month', t.res_time), DATE_TRUNC('year', t.res_time)");
            ps.setInt(1, uId);
            ps.setString(2, timestampMonth);
            ps.setString(3, timestampYear);
            ps.setInt(4, uId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return rs.getLong("monthly_income");
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return 0L;

    }

    public Long allTimeUserIncome(int uId) {

        try (Connection con = ConnectionUtility.createConnection()) {
            PreparedStatement ps = con.prepareStatement("SELECT  SUM(t.amount) AS all_accounts_all_time " +
                    "\tFROM transactions t \n " +
                    "\tWHERE t.receiving_id IN" +
                    "(" +
                    "SELECT uwa .account_id " +
                    "FROM users_with_accounts uwa " +
                    "WHERE uwa.user_id = ? " +
                    ") AND t.status_id = 2 AND " +
                    "t.sending_id NOT IN(\n " +
                    "\tSELECT uwa .account_id\n " +
                    "\tFROM users_with_accounts uwa\n " +
                    "\tWHERE uwa.user_id = ?)");
            ps.setInt(1, uId);
            ps.setInt(2, uId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return rs.getLong("all_accounts_all_time");
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            throw new RuntimeException(e);
        }
        return 0L;

    }


}


// (update(approve/deny) give resolve time, descriptionId, change amount in accounts
// delete-cancel a transaction as long as it hasnt been approved
