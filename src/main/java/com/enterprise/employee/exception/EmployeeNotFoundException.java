package com.enterprise.employee.exception;

/**
 * Exception thrown when an Employee cannot be found by the requested identifier.
 */
public class EmployeeNotFoundException extends RuntimeException {

    public EmployeeNotFoundException(String message) {
        super(message);
    }

    public EmployeeNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
