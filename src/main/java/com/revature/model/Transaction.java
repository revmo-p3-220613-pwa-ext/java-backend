package com.revature.model;

import java.sql.Timestamp;
import java.util.Objects;

public class Transaction {

    private int transactionId;
    private int requestId;
    private int sendingId;
    private int receivingId;
    private Timestamp requestTime;
    private Timestamp resolveTime;
    private boolean approve;
    private int status_id;
    private int descriptionId;
    private long balance;


    public Transaction(int transactionId, int requesterId, int sendingId, int receivingId,
                       Timestamp requestTime, Timestamp resolveTime, boolean approve,
                       int status_id, int descriptionId, long balance) {

        this.transactionId = transactionId;
        this.requestId = requesterId;
        this.sendingId = sendingId;
        this.receivingId = receivingId;
        this.requestTime = requestTime;
        this.resolveTime = resolveTime;
        this.approve = approve;
        this.status_id = status_id;
        this.descriptionId = descriptionId;
        this.balance = balance;
    }

    public Transaction() {

    }

    public int getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(int transactionId) {
        this.transactionId = transactionId;
    }

    public int getSendingId() {
        return sendingId;
    }

    public void setSendingId(int sendingId) {
        this.sendingId = sendingId;
    }

    public int getReceivingId() {
        return receivingId;
    }

    public void setReceivingId(int receivingId) {
        this.receivingId = receivingId;
    }

    public Timestamp getRequestTime() {
        return requestTime;
    }

    public void setRequestTime(Timestamp requestTime) {
        this.requestTime = requestTime;
    }

    public Timestamp getResolveTime() {
        return resolveTime;
    }

    public void setResolveTime(Timestamp resolveTime) {
        this.resolveTime = resolveTime;
    }


    public int getStatus_id() {return status_id;}

    public void setApproved(int status) {
        this.status_id = status;

    }

    public int getRequestId() {
        return requestId;
    }

    public void setRequestId(int requestId) {
        this.requestId = requestId;
    }

    public int getDescriptionId() {
        return descriptionId;
    }

    public void setDescriptionId(int descriptionId) {
        this.descriptionId = descriptionId;
    }


    public void setBalance(long balance){this.balance = balance;}

    public long getBalance(){return balance;}


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Transaction that = (Transaction) o;
        return transactionId == that.transactionId && sendingId == that.sendingId && receivingId == that.receivingId && status_id == that.status_id && descriptionId == that.descriptionId && balance == that.balance && Objects.equals(requestTime, that.requestTime) && Objects.equals(resolveTime, that.resolveTime);
    }

    @Override
    public int hashCode() {
        return Objects.hash(transactionId, sendingId, receivingId, requestTime, resolveTime, status_id, descriptionId, balance);
    }

    @Override
    public String toString() {
        return "Transaction{" +
                "transactionId=" + transactionId +
                ", sendingId=" + sendingId +
                ", receivingId=" + receivingId +
                ", requestTime=" + requestTime +
                ", resolveTime=" + resolveTime +
                ", approved=" + status_id +
                ", descriptionId=" + descriptionId +
                ", transaction amount=" + balance +
                '}';
    }
}
