package com.enterprise.employee.service;

import com.enterprise.employee.dto.EmployeeDTO;

import java.util.List;
import java.util.Optional;

/**
 * Service interface defining the contract for Employee business operations.
 */
public interface EmployeeService {

    /**
     * Retrieve all employees from the system.
     *
     * @return list of all employees as DTOs
     */
    List<EmployeeDTO> getAllEmployees();

    /**
     * Retrieve a single employee by its primary key id.
     *
     * @param id the employee id
     * @return the employee DTO
     * @throws com.enterprise.employee.exception.EmployeeNotFoundException if not found
     */
    EmployeeDTO getEmployeeById(Long id);

    /**
     * Retrieve a single employee by its business employee ID.
     *
     * @param employeeId the business employee ID
     * @return Optional containing the employee DTO if found
     */
    Optional<EmployeeDTO> getEmployeeByEmployeeId(String employeeId);

    /**
     * Create a new employee record.
     *
     * @param employeeDTO the employee payload
     * @return the persisted employee DTO
     */
    EmployeeDTO createEmployee(EmployeeDTO employeeDTO);

    /**
     * Update an existing employee.
     *
     * @param id the id of the employee to update
     * @param employeeDTO the new payload
     * @return the updated employee DTO
     * @throws com.enterprise.employee.exception.EmployeeNotFoundException if not found
     */
    EmployeeDTO updateEmployee(Long id, EmployeeDTO employeeDTO);

    /**
     * Delete an employee by id.
     *
     * @param id the id of the employee to delete
     * @throws com.enterprise.employee.exception.EmployeeNotFoundException if not found
     */
    void deleteEmployee(Long id);
}
