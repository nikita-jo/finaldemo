package com.enterprise.employee.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
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
 * Employee JPA Entity mapped to the EMPLOYEES table.
 * Represents a single employee record in the system.
 */
@Entity
@Table(name = "EMPLOYEES")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Employee {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "ID")
    private Long id;

    @NotBlank(message = "Employee ID is required")
    @Column(name = "EMPLOYEE_ID", nullable = false, unique = true, length = 50)
    private String employeeId;

    @NotBlank(message = "First name is required")
    @Column(name = "FIRST_NAME", nullable = false, length = 100)
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Column(name = "LAST_NAME", nullable = false, length = 100)
    private String lastName;

    @NotBlank(message = "Email is required")
    @Email(message = "Email must be a valid email address")
    @Column(name = "EMAIL", nullable = false, unique = true, length = 150)
    private String email;

    @NotBlank(message = "Department is required")
    @Column(name = "DEPARTMENT", nullable = false, length = 100)
    private String department;

    @NotBlank(message = "Designation is required")
    @Column(name = "DESIGNATION", nullable = false, length = 100)
    private String designation;

    @NotNull(message = "Salary is required")
    @Positive(message = "Salary must be a positive value")
    @Column(name = "SALARY", nullable = false, precision = 15, scale = 2)
    private BigDecimal salary;

    @NotNull(message = "Joining date is required")
    @Column(name = "JOINING_DATE", nullable = false)
    private LocalDate joiningDate;
}
