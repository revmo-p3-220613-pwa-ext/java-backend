package com.revature.service;

import com.revature.dao.AccountDao;
import com.revature.dao.UserDao;
import com.revature.exception.InvalidParameterException;
import com.revature.model.Account;
import com.revature.model.User;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.Answer;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.*;

public class AccountServiceTest {
    @Test
    public void testOpenAccountPositive() throws InvalidParameterException {
        // Arrange

        AccountDao mockedObject = mock(AccountDao.class);
        Account mockAccount = new Account(0, 1, 0);
        Account returnAccount = new Account(1, 1, null, 0);
        Map<String, String> addAccount = new HashMap<>();
        addAccount.put("typeId", "1");
        addAccount.put("balance", "0");

        when(mockedObject.openAccount(mockAccount)).thenReturn(returnAccount);

        AccountService accountService = new AccountService(mockedObject);

        // Act
        Account actual = accountService.openAccount(addAccount);
//
//        // Assert
        Account expected = new Account(1, 1, 0);
        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testGetAccountsByEmailPositive() throws SQLException, InvalidParameterException {
        // Arrange
        AccountDao mockedObject = mock(AccountDao.class);
        String email = "jd80@a.ca";
        List<Account> accountList = new ArrayList<>();
        accountList.add(new Account(1, 1, 20));
        accountList.add(new Account(2, 1, 15));
        accountList.add(new Account(3, 1, 30));

        when(mockedObject.getAccountsByEmail(email)).thenReturn(accountList);

        AccountService accountService = new AccountService(mockedObject);

        // Act
//        List<Account> actual = accountService.getAccountsByEmail(email);
//
//        // Assert
        List<Account> expected = new ArrayList<>(accountList);
//        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testGetAccountsByEmailAndAccountId() throws SQLException, InvalidParameterException {
        // Arrange
        AccountDao mockedObject = mock(AccountDao.class);
        String email = "jd80@a.ca";
        int id = 3;

        Account account = (new Account(1, 1, 20));
        Account account2 = (new Account(2, 1, 15));
        Account account3 = (new Account(3, 1, 30));

        when(mockedObject.getAccountByEmailAndAccountId(email, id)).thenReturn(account3);

        AccountService accountService = new AccountService(mockedObject);

        // Act
//        Account actual = accountService.getAccountByEmailAndAccountId(email, id);
//
//        // Assert
        Account expected = new Account(3, 1, 30);
//        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testLinkToAccountPositive() throws InvalidParameterException, SQLException {
        // Arrange
        AccountDao mockedObject = mock(AccountDao.class);
        UserService userService = mock(UserService.class);
        AccountService accountService = new AccountService(mockedObject, userService);
        Account mockAccount = new Account(1, 1, 0);
        User mockUser = new User(1, "John", "Doe", "jd@outlook.com", "password",
                "1234567897", "user");
        List<String> mockOwners = new ArrayList<>();
        mockOwners.add("Jenny Johnson");
        mockOwners.add("Barry Allen");
        String mockReturn = ("Account " + mockAccount.getAccountId() + " successfully linked to user" +
                " " + mockUser.getUserId() + "!");
        when(mockedObject.obtainListOfAccountOwners(mockAccount.getAccountId())).thenReturn(mockOwners);
        when(userService.getUserByEmail(eq(mockUser.getEmail()))).thenReturn(mockUser);
        when(mockedObject.linkUserToAccount(1, 1)).thenReturn(mockReturn);


        // Act
//        String actual = accountService.linkUserToAccount(mockAccount.getAccountId(), mockUser.getEmail());
//
//        // Assert
        String expected = new String("Account " + 1 + " successfully linked to user " + 1 + "!");
//        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testLinkToAccountNoUser() throws InvalidParameterException, SQLException {
        // Arrange
        AccountDao mockedObject = mock(AccountDao.class);
        UserService userService = mock(UserService.class);
        AccountService accountService = new AccountService(mockedObject, userService);
        Account mockAccount = new Account(1, 1, 0);
        User mockUser = new User(1, "John", "Doe", "jd@outlook.com", "password",
                "1234567897", "user");
        List<String> mockOwners = new ArrayList<>();
        mockOwners.add("Jenny Johnson");
        mockOwners.add("Barry Allen");
        List<String> mockReturn = new ArrayList<>();
        mockReturn.add("User not found");
        when(mockedObject.obtainListOfAccountOwners(mockAccount.getAccountId())).thenReturn(mockOwners);
        when(userService.getUserByEmail(eq(mockUser.getEmail()))).thenReturn(null);

        try {
            accountService.linkUserToAccount(1, "prestiege@ww.com");
            fail();
        } catch (InvalidParameterException e) {
            // Act
            List<String> actual = e.getMessages();

            // Assert
//            Assertions.assertEquals(mockReturn, actual);
        }
    }

    @Test
    public void testLinkToAccountAlreadyLinked() throws InvalidParameterException, SQLException {
        // Arrange
        AccountDao mockedObject = mock(AccountDao.class);
        UserService userService = mock(UserService.class);
        AccountService accountService = new AccountService(mockedObject, userService);
        Account mockAccount = new Account(1, 1, 0);
        User mockUser = new User(1, "John", "Doe", "jd@outlook.com", "password",
                "1234567897", "user");
        List<String> mockOwners = new ArrayList<>();
        mockOwners.add("Jenny Johnson");
        mockOwners.add("Barry Allen");
        mockOwners.add("John Doe");
        List<String> mockReturn = new ArrayList<>();
        mockReturn.add("User " + mockUser.getUserId() + " already linked to account " + 1);
        when(mockedObject.obtainListOfAccountOwners(mockAccount.getAccountId())).thenReturn(mockOwners);
        when(userService.getUserByEmail(eq(mockUser.getEmail()))).thenReturn(mockUser);

        try {
            accountService.linkUserToAccount(1, "jd@outlook.com");
            fail();
        } catch (InvalidParameterException e) {
            // Act
            List<String> actual = e.getMessages();

            // Assert
//            Assertions.assertEquals(mockReturn, actual);
        }
    }

    @Test
    public void testUnlinkToAccount() throws InvalidParameterException, SQLException {
        // Arrange

        AccountDao mockedObject = mock(AccountDao.class);
        UserService userService = mock(UserService.class);
        AccountService accountService = new AccountService(mockedObject, userService);
        Account mockAccount = new Account(1, 1, 0);
        User mockUser = new User(1, "John", "Doe", "jd@outlook.com", "password",
                "1234567897", "user");
        List<String> mockOwners = new ArrayList<>();
        mockOwners.add("Jenny Johnson");
        mockOwners.add("Barry Allen");
        mockOwners.add("John Doe");
        String mockReturn = ("Account " + mockAccount.getAccountId() + " successfully unlinked from user" +
                " " + mockUser.getUserId() + "!");
        when(mockedObject.obtainListOfAccountOwners(mockAccount.getAccountId())).thenReturn(mockOwners);
        when(userService.getUserByEmail(eq(mockUser.getEmail()))).thenReturn(mockUser);
        when(mockedObject.unlinkUserFromAccount(1, 1)).thenReturn(mockReturn);


        // Act
        String actual = accountService.unlinkUserFromAccount(mockAccount.getAccountId(), mockUser.getEmail());
//
//        // Assert
        String expected = new String("Account " + 1 + " successfully unlinked from user " + 1 + "!");
        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testUnlinkToAccountNoUser() throws InvalidParameterException, SQLException {
        // Arrange
        AccountDao mockedObject = mock(AccountDao.class);
        UserService userService = mock(UserService.class);
        AccountService accountService = new AccountService(mockedObject, userService);
        Account mockAccount = new Account(1, 1, 0);
        User mockUser = new User(1, "John", "Doe", "jd@outlook.com", "password",
                "1234567897", "user");
        List<String> mockOwners = new ArrayList<>();
        mockOwners.add("Jenny Johnson");
        mockOwners.add("Barry Allen");
        List<String> mockReturn = new ArrayList<>();
        mockReturn.add("User not found");
        when(mockedObject.obtainListOfAccountOwners(mockAccount.getAccountId())).thenReturn(mockOwners);
        when(userService.getUserByEmail(eq(mockUser.getEmail()))).thenReturn(null);

        try {
            accountService.unlinkUserFromAccount(1, "prestiege@ww.com");
            fail();
        } catch (InvalidParameterException e) {
            // Act
            List<String> actual = e.getMessages();

            // Assert
            Assertions.assertEquals(mockReturn, actual);
        }
    }

    @Test
    public void testUnlinkToAccountNotLinked() throws InvalidParameterException, SQLException {
        // Arrange
        AccountDao mockedObject = mock(AccountDao.class);
        UserService userService = mock(UserService.class);
        AccountService accountService = new AccountService(mockedObject, userService);
        Account mockAccount = new Account(1, 1, 0);
        User mockUser = new User(1, "John", "Doe", "jd@outlook.com", "password",
                "1234567897", "user");
        List<String> mockOwners = new ArrayList<>();
        mockOwners.add("Jenny Johnson");
        mockOwners.add("Barry Allen");
        List<String> mockReturn = new ArrayList<>();
        mockReturn.add("User " + mockUser.getUserId() + " not linked to account " + 1);
        when(mockedObject.obtainListOfAccountOwners(mockAccount.getAccountId())).thenReturn(mockOwners);
        when(userService.getUserByEmail(eq(mockUser.getEmail()))).thenReturn(mockUser);

        try {
            accountService.unlinkUserFromAccount(1, "jd@outlook.com");
            fail();
        } catch (InvalidParameterException e) {
            // Act
            List<String> actual = e.getMessages();

            // Assert
            Assertions.assertEquals(mockReturn, actual);
        }
    }

    @Test
    public void testDeleteAccountPositive() throws InvalidParameterException, SQLException {
        // Arrange

        AccountDao mockedObject = mock(AccountDao.class);
        Account mockAccount = new Account(1, 1, 0);
        List<String> mockowners = new ArrayList<>();
        mockowners.add("John Doe");
        User mockuser = new User(1, "John", "Doe", "jd@outlook.com", "password",
                "1234567897", "user");
        String mockReturn = ("1");

        when(mockedObject.getAccountsById(1)).thenReturn(mockAccount);
        when(mockedObject.obtainListOfAccountOwners(1)).thenReturn(mockowners);
        when(mockedObject.deleteAccount(mockAccount.getAccountId())).thenReturn(mockReturn);

        AccountService accountService = new AccountService(mockedObject);

        // Act
        String actual = accountService.deleteAccount(mockAccount.getAccountId());
//
//        // Assert
        String expected = new String("1");
        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testObtainListOfAccountOwners() throws InvalidParameterException, SQLException {
        // Arrange

        AccountDao mockedObject = mock(AccountDao.class);
        Account mockAccount = new Account(1, 1, 0);
        List<String> mockowners = new ArrayList<>();
        mockowners.add("John Doe");
        mockowners.add("Jane Doe");
        mockowners.add("Jack Black");

        when(mockedObject.obtainListOfAccountOwners(mockAccount.getAccountId())).thenReturn(mockowners);

        AccountService accountService = new AccountService(mockedObject);

        // Act
        List<String> actual = accountService.obtainListOfAccountOwners(1);
//
//        // Assert
        List<String> expected = mockowners;
        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testDeleteAccountBalanceNotZero() throws SQLException {
        // Arrange

        AccountDao mockedObject = mock(AccountDao.class);
        AccountService accountService = new AccountService(mockedObject);

        Account mockAccount = new Account(1, 1, 500);

        List<String> mockReturn = new ArrayList<>();
        mockReturn.add("Account balance must be 0!");

        when(mockedObject.getAccountsById(1)).thenReturn(mockAccount);
        try {
            accountService.deleteAccount(1);
            fail();
        } catch (InvalidParameterException e) {
            // Act
            List<String> actual = e.getMessages();
//
//        // Assert
            List<String> expected = mockReturn;
            Assertions.assertEquals(expected, actual);
        }
    }

    @Test
    public void testDeleteAccountMoreThanOneLinkedUser() throws SQLException {
        // Arrange

        AccountDao mockedObject = mock(AccountDao.class);
        AccountService accountService = new AccountService(mockedObject);

        Account mockAccount = new Account(1, 1, 0);

        List<String> mockReturn = new ArrayList<>();
        mockReturn.add("An account with more than one linked user cannot be deleted!");
        List<String> mockowners = new ArrayList<>();
        mockowners.add("John Doe");
        mockowners.add("Jane Doe");
        mockowners.add("Jack Black");

        when(mockedObject.getAccountsById(1)).thenReturn(mockAccount);
        when(mockedObject.obtainListOfAccountOwners(1)).thenReturn(mockowners);

        try {
            accountService.deleteAccount(1);
            fail();
        } catch (InvalidParameterException e) {
            // Act
            List<String> actual = e.getMessages();
//
//        // Assert
            Assertions.assertEquals(mockReturn, actual);
        }
    }

    @Test
    public void testDeleteAccountbothFail() throws SQLException {
        // Arrange

        AccountDao mockedObject = mock(AccountDao.class);
        AccountService accountService = new AccountService(mockedObject);

        Account mockAccount = new Account(1, 1, 2000);

        List<String> mockReturn = new ArrayList<>();
        mockReturn.add("Account balance must be 0!");
        mockReturn.add("An account with more than one linked user cannot be deleted!");

        List<String> mockowners = new ArrayList<>();
        mockowners.add("John Doe");
        mockowners.add("Jane Doe");
        mockowners.add("Jack Black");

        when(mockedObject.getAccountsById(1)).thenReturn(mockAccount);
        when(mockedObject.obtainListOfAccountOwners(1)).thenReturn(mockowners);

        try {
            accountService.deleteAccount(1);
            fail();
        } catch (InvalidParameterException e) {
            // Act
            List<String> actual = e.getMessages();
//
//        // Assert
            Assertions.assertEquals(mockReturn, actual);
        }
    }
}

