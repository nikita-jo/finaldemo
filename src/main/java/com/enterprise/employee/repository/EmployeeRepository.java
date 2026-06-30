package com.enterprise.employee.repository;

import com.enterprise.employee.entity.Employee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for the Employee entity.
 * Provides CRUD operations and custom finder methods.
 */
@Repository
public interface EmployeeRepository extends JpaRepository<Employee, Long> {

    /**
     * Find an employee by their unique business employee ID.
     *
     * @param employeeId the business employee ID
     * @return Optional containing the Employee if found
     */
    Optional<Employee> findByEmployeeId(String employeeId);

    /**
     * Find all employees belonging to a given department.
     *
     * @param department the department name
     * @return list of matching employees
     */
    List<Employee> findByDepartment(String department);

    /**
     * Find an employee by their unique email address.
     *
     * @param email the email address
     * @return Optional containing the Employee if found
     */
    Optional<Employee> findByEmail(String email);

    /**
     * Check whether an employee exists with the given business employee ID.
     *
     * @param employeeId the business employee ID
     * @return true if exists
     */
    boolean existsByEmployeeId(String employeeId);
}
