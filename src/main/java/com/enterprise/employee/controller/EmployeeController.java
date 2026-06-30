package com.enterprise.employee.controller;

import com.enterprise.employee.dto.EmployeeDTO;
import com.enterprise.employee.service.EmployeeService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * REST controller exposing Employee endpoints under /api/v1/employees.
 */
@RestController
@RequestMapping("/api/v1/employees")
public class EmployeeController {

    private static final Logger log = LoggerFactory.getLogger(EmployeeController.class);

    private final EmployeeService employeeService;

    public EmployeeController(EmployeeService employeeService) {
        this.employeeService = employeeService;
    }

    /**
     * GET /api/v1/employees - return all employees.
     */
    @GetMapping
    public ResponseEntity<List<EmployeeDTO>> getAllEmployees() {
        log.debug("REST: GET /api/v1/employees");
        List<EmployeeDTO> employees = employeeService.getAllEmployees();
        log.info("Returning {} employees", employees.size());
        return ResponseEntity.ok(employees);
    }

    /**
     * GET /api/v1/employees/{id} - return a single employee.
     */
    @GetMapping("/{id}")
    public ResponseEntity<EmployeeDTO> getEmployeeById(@PathVariable Long id) {
        log.debug("REST: GET /api/v1/employees/{}", id);
        EmployeeDTO employee = employeeService.getEmployeeById(id);
        return ResponseEntity.ok(employee);
    }

    /**
     * POST /api/v1/employees - create a new employee.
     */
    @PostMapping
    public ResponseEntity<EmployeeDTO> createEmployee(@Valid @RequestBody EmployeeDTO employeeDTO) {
        log.debug("REST: POST /api/v1/employees");
        EmployeeDTO created = employeeService.createEmployee(employeeDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    /**
     * PUT /api/v1/employees/{id} - update an existing employee.
     */
    @PutMapping("/{id}")
    public ResponseEntity<EmployeeDTO> updateEmployee(
            @PathVariable Long id, @Valid @RequestBody EmployeeDTO employeeDTO) {
        log.debug("REST: PUT /api/v1/employees/{}", id);
        EmployeeDTO updated = employeeService.updateEmployee(id, employeeDTO);
        return ResponseEntity.ok(updated);
    }

    /**
     * DELETE /api/v1/employees/{id} - delete an employee.
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteEmployee(@PathVariable Long id) {
        log.debug("REST: DELETE /api/v1/employees/{}", id);
        employeeService.deleteEmployee(id);
        return ResponseEntity.noContent().build();
    }
}
