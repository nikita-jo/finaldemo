package com.enterprise.employee.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDate;

/**
 * Data Transfer Object for Employee.
 * Decouples the persistence entity from the API contract.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmployeeDTO {

    private Long id;

    @NotBlank(message = "Employee ID is required")
    private String employeeId;

    @NotBlank(message = "First name is required")
    private String firstName;

    @NotBlank(message = "Last name is required")
    private String lastName;

    @NotBlank(message = "Email is required")
    @Email(message = "Email must be a valid email address")
    private String email;

    @NotBlank(message = "Department is required")
    private String department;

    @NotBlank(message = "Designation is required")
    private String designation;

    @NotNull(message = "Salary is required")
    @Positive(message = "Salary must be a positive value")
    private BigDecimal salary;

    @NotNull(message = "Joining date is required")
    private LocalDate joiningDate;
}
